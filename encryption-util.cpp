#include "sodium.h" // IWYU pragma: export
#include <algorithm>
#include <cstring>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>

constexpr size_t keyLength = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
constexpr size_t saltLength = crypto_pwhash_SALTBYTES;
static bool silentMode = false;

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

void setEcho(bool enable) {
#ifdef _WIN32
   HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
   DWORD mode;
   GetConsoleMode(hStdin, &mode);
   mode = enable ? (mode | ENABLE_ECHO_INPUT) : (mode & ~ENABLE_ECHO_INPUT);
   SetConsoleMode(hStdin, mode);
#else
   termios tty;
   tcgetattr(STDIN_FILENO, &tty);
   if (enable) tty.c_lflag |= ECHO;
   else        tty.c_lflag &= ~ECHO;
   tcsetattr(STDIN_FILENO, TCSANOW, &tty);
#endif
}

std::string readHiddenLine(const char *msg) {
   printf("%s", msg);
   setEcho(false);
   std::string line;
   std::getline(std::cin >> std::ws, line);
   setEcho(true);
#ifndef _WIN32
   printf("\n");
#endif
   return line;
}

std::vector<std::string> split(const std::string &string, char delimiter) {
   size_t delimiterCount = std::count(string.begin(), string.end(), delimiter);
   std::vector<std::string> output;
   output.reserve(delimiterCount + 1);

   std::stringstream stream (string);
   std::string piece;

   while (std::getline(stream, piece, delimiter)) {
      output.push_back(piece);
   }
   return output;
}

bool setMasterPassword(std::string &outPass) {
   std::string pass1 = readHiddenLine("New password: ");
   std::string pass2 = readHiddenLine("Confirm password: ");
   if (pass1 != pass2) {
      printf("Passwords do not match. Try again.\n");
      sodium_memzero(&pass1[0], pass1.size());
      sodium_memzero(&pass2[0], pass2.size());
      return setMasterPassword(outPass);
   }
   if (pass1.size() < 8 || pass1.find_first_of("1234567890") == std::string::npos || pass1.find_first_of("!@#$%^&*())_+-=?/,.<>;:'\"\\|{}[]`~") == std::string::npos) {
      printf("Password is insecure. It must be longer than 8 characters and use both a digit and a symbol. Try again.\n");
      sodium_memzero(&pass1[0], pass1.size());
      sodium_memzero(&pass2[0], pass2.size());
      return setMasterPassword(outPass);
   }
   outPass = pass1;
   sodium_memzero(&pass1[0], pass1.size());
   sodium_memzero(&pass2[0], pass2.size());
   return true;
}

void deriveKey(std::string &password, const unsigned char *salt, unsigned char *outKey) {
   if (crypto_pwhash(outKey, keyLength, password.c_str(), password.size(), salt, crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE, crypto_pwhash_ALG_ARGON2ID13) != 0) {
      printf("Key derivation failed.\n");
      sodium_memzero(outKey, keyLength);
      sodium_memzero(&password[0], password.size());
      exit(EXIT_FAILURE);
   }
   sodium_memzero(&password[0], password.size());
}

bool encryptBlob(const unsigned char *key, const std::string &plaintext, std::vector<unsigned char> &out) {
   unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
   randombytes_buf(nonce, sizeof(nonce));
   out.resize(sizeof(nonce) + plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
   memcpy(out.data(), nonce, sizeof(nonce));

   unsigned long long ciphertext_len;
   crypto_aead_xchacha20poly1305_ietf_encrypt(out.data() + sizeof(nonce), &ciphertext_len, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size(), nullptr, 0, nullptr, nonce, key);
   out.resize(sizeof(nonce) + ciphertext_len);
   return true;
}

void decryptBlob(unsigned char *key, const std::vector<unsigned char> &in, std::string &plaintext) {
   constexpr size_t NB = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
   if (in.size() < NB + crypto_aead_xchacha20poly1305_ietf_ABYTES) {
      printf("Invalid password.\n");
      sodium_memzero(key, keyLength);
      exit(EXIT_FAILURE);
   }

   const unsigned char *nonce = in.data();
   const unsigned char *ciphertext = in.data() + NB;
   unsigned long long ciphertext_len = in.size() - NB;
   std::vector<unsigned char> out(ciphertext_len);
   unsigned long long out_len;

   if (crypto_aead_xchacha20poly1305_ietf_decrypt(out.data(), &out_len, nullptr, ciphertext, ciphertext_len, nullptr, 0, nonce, key) != 0) {
      printf("Invalid password.\n");
      sodium_memzero(key, keyLength);
      exit(EXIT_FAILURE);
   }
   plaintext.assign(out.begin(), out.begin() + out_len);
}

void saveVault(const unsigned char *key, const std::string &plaintext, const std::string &filename, const unsigned char *salt) {
   std::vector<unsigned char> out;
   encryptBlob(key, plaintext, out);
   std::ofstream pf(filename, std::ios::binary | std::ios::trunc);
   pf.write(reinterpret_cast<const char*>(salt), saltLength);
   pf.write(reinterpret_cast<char*>(out.data()), out.size());
   if (!silentMode) printf("Wrote to %s\n", filename.c_str());
}

void printLines(const std::vector<std::string> &lines) {
   size_t i = 0;
   for (const std::string &line: lines) {
      printf("%5llu: %s\n", ++i, line.c_str());
   }
}

void saveLines(std::vector<std::string> &lines, const unsigned char *key, const std::string &filename, const unsigned char *salt) {
   std::string joined;
   for (std::string &line: lines) {
      joined += line + '\n';
      sodium_memzero(&line[0], line.size());
   }
   saveVault(key, joined, filename, salt);
   sodium_memzero(&joined[0], joined.size());
}

void appendU64(std::string &out, uint64_t value) {
   size_t size = sizeof(value);
   char buffer[size];
   memcpy(buffer, &value, size);
   out.append(buffer, size);
}

bool readU64(const std::string &in, size_t &pos, uint64_t &out) {
   if (pos + sizeof(out) > in.size()) return false;
   memcpy(&out, in.data() + pos, sizeof(out));
   pos += sizeof(out);
   return true;
}

void appendFile(std::string &plainText, std::string &path, std::ifstream &stream) {
   if (!silentMode) printf("Encrypting %s...\n", path.c_str());
   std::string contents {std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
   plainText.reserve(plainText.size() + path.size() + contents.size() + sizeof(uint64_t) * 2);
   appendU64(plainText, path.size());
   plainText += path;
   appendU64(plainText, contents.size());
   plainText += contents;
   sodium_memzero(&contents[0], contents.size());
}

std::ifstream openFile(const std::string &filename) {
   std::ifstream stream (filename, std::ios::binary);
   if (!stream.is_open()) {
      printf("Could not open '%s'.\n", filename.c_str());
      exit(EXIT_FAILURE);
   }
   return stream;
}

std::vector<unsigned char> readEncryptedFile(unsigned char *salt, std::ifstream &stream) {
   stream.read(reinterpret_cast<char*>(salt), saltLength);
   std::vector<unsigned char> blob((std::istreambuf_iterator<char>(stream)), {});
   stream.close();
   return blob;
}

void helpCommand() {
   printf("password-manager\n");
   printf("Usage:\n\t./password-manager [args] [command]\n");
   printf("Commands:\n");
   printf("\t-h                       show help.\n");
   printf("\t-m  [file]               reset password.\n");
   printf("\t-v  [file]               view file.\n");
   printf("\t-e  [file]               edit file.\n");
   printf("\t-i  [file]               insert into file.\n");
   printf("\t-d  [file]               delete from file.\n");
   printf("\t-a  [file]               append to file.\n");
   printf("\t-r  [file]               remove file/directories.\n");
   printf("\t-ea [in1,in2,...] [out]  combine files/directories into an encrypted archive.\n");
   printf("\t-da [in] [out]           decrypt an archive.\n");
   printf("Args:\n");
   printf("\t-s                       silent mode.\n");
}

void resetPassword(std::string &plainText, std::string &filename) {
   std::string newPass;
   setMasterPassword(newPass);
   unsigned char newSalt[saltLength];
   unsigned char newKey[keyLength];
   randombytes_buf(newSalt, saltLength);
   deriveKey(newPass, newSalt, newKey);
   saveVault(newKey, plainText, filename, newSalt);
   sodium_memzero(newKey, keyLength);
}

void viewFile(std::string &plainText) {
   std::vector<std::string> lines = split(plainText, '\n');
   printLines(lines);
}

void editFile(std::string &plainText, std::string &filename, unsigned char *salt, unsigned char *key) {
   std::vector<std::string> lines = split(plainText, '\n');
   while (true) {
      printLines(lines);
      printf("\nSelect line to edit (%d-%llu or \"quit\" to quit): ", 1, lines.size());
      int i = 0;
      std::cin >> i;
      if (i <= 0 || i - 1 >= lines.size() || std::cin.fail()) break;
      i -= 1;

      std::string l;
      printf(" > ");
      std::getline(std::cin >> std::ws, l);
      lines[i] = l;
      sodium_memzero(&l[0], l.size());
   }
   saveLines(lines, key, filename, salt);
}

void insertIntoFile(std::string &plainText, std::string &filename, unsigned char *salt, unsigned char *key) {
   std::vector<std::string> lines = split(plainText, '\n');
   while (true) {
      printLines(lines);
      printf("\nIndex to insert in (0-start, 1-after first line, %llu-end or \"quit\" to quit): ", lines.size());
      int i = 0;
      std::cin >> i;
      if (i < 0 || i >= lines.size() || std::cin.fail()) break;

      std::string l;
      printf(" > ");
      std::getline(std::cin >> std::ws, l);
      lines.insert(lines.begin() + i, l);
      sodium_memzero(&l[0], l.size());
   }
   saveLines(lines, key, filename, salt);
}

void deleteLinesFromFile(std::string &plainText, std::string &filename, unsigned char *salt, unsigned char *key) {
   std::vector<std::string> lines = split(plainText, '\n');
   while (true) {
      printLines(lines);
      printf("\nSelect line to delete (%d-%llu or \"quit\" to quit): ", 1, lines.size());
      int i = 0;
      std::cin >> i;
      if (i <= 0 || i - 1 >= lines.size() || std::cin.fail()) break;
      lines.erase(lines.begin() + (i - 1));
   }
   saveLines(lines, key, filename, salt);
}

void addToFile(std::string &plainText, std::string &filename, unsigned char *salt, unsigned char *key) {
   printf("Add new secrets. \"quit\" to stop.\n");
   while (true) {
      printf(" > ");
      std::string secret;
      std::getline(std::cin >> std::ws, secret);

      if (secret == "quit") break;
      plainText += secret + "\n";
      sodium_memzero(&secret[0], secret.size());
   }
   saveVault(key, plainText, filename, salt);
}

void removeFiles(int argc, char *argv[]) {
   for (int i = 1; i < argc - 1; ++i) {
      std::string path = argv[i];
      if (std::filesystem::exists(path)) {
         std::filesystem::remove_all(path);
      }
      if (!silentMode) printf("Deleting %s.\n", path.c_str());
      sodium_memzero(&path[0], path.size());
   }
   if (!silentMode) printf("Deletion done.\n");
}

void encryptArchive(int argc, char *argv[]) {
   unsigned char salt[saltLength];
   unsigned char key[keyLength];
   std::string pass;
   setMasterPassword(pass);
   randombytes_buf(salt, saltLength);
   deriveKey(pass, salt, key);
   std::string plainText;
   for (int i = 1; i < argc - 1; ++i) {
      std::string path = argv[i];
      if (!std::filesystem::exists(path)) {
         printf("File '%s' does not exist.\n", path.c_str());
         exit(EXIT_FAILURE);
      }
      if (std::filesystem::is_directory(path)) {
         for (const auto &file: std::filesystem::recursive_directory_iterator(path)) {
            if (!file.is_regular_file()) continue;
            std::string path = file.path().string();
            std::ifstream stream = openFile(path);
            appendFile(plainText, path, stream);
         }
      }
      else if (std::filesystem::is_regular_file(path)) {
         std::ifstream stream = openFile(path);
         appendFile(plainText, path, stream);
      }
      sodium_memzero(&path[0], path.size());
   }
   saveVault(key, plainText, argv[argc-1], salt);
   sodium_memzero(&plainText[0], plainText.size());
   sodium_memzero(key, keyLength);
   if (!silentMode) printf("Archive encryption complete.\n");
}

void decryptArchive(int argc, char *argv[]) {
   std::ifstream stream = openFile(argv[1]);
   unsigned char salt[saltLength];
   unsigned char key[keyLength];
   std::vector<unsigned char> blob = readEncryptedFile(salt, stream);
   std::string plainText;
   std::string masterPassword = readHiddenLine("Input password: ");
   deriveKey(masterPassword, salt, key);
   decryptBlob(key, blob, plainText);
   size_t pos = 0;
   while (pos < plainText.size()) {
      uint64_t nameLen;
      if (!readU64(plainText, pos, nameLen) || pos + nameLen > plainText.size()) {
         printf("Corrupted archive (bad path entry).\n");
         sodium_memzero(&plainText[0], plainText.size());
         exit(EXIT_FAILURE);
      }
      std::string rel = plainText.substr(pos, nameLen);
      pos += nameLen;

      uint64_t dataLen;
      if (!readU64(plainText, pos, dataLen) || pos + dataLen > plainText.size()) {
         printf("Corrupted archive (bad data entry).\n");
         sodium_memzero(&rel[0], rel.size());
         sodium_memzero(&plainText[0], plainText.size());
         exit(EXIT_FAILURE);
      }

      std::filesystem::path outPath = std::filesystem::path(argv[2]) / rel;
      if (!silentMode) printf("Decrypting %s...\n", outPath.string().c_str());

      std::filesystem::create_directories(outPath.parent_path());
      std::ofstream out(outPath, std::ios::binary | std::ios::trunc);
      out.write(plainText.data() + pos, dataLen);
      pos += dataLen;
      sodium_memzero(&rel[0], rel.size());
   }
   sodium_memzero(&plainText[0], plainText.size());
   sodium_memzero(key, keyLength);
   if (!silentMode) printf("Archive decryption complete.\n");
}

int main(int argc, char *argv[]) {
   for (int i = 1; i < argc; ++i) {
      if (strcmp(argv[i], "-s") == 0) {
         silentMode = true;
      }
      else {
         argv = &argv[i];
         argc -= i;
         break;
      }
   }

   if (argc < 2 || (argc > 0 && (strcmp(argv[0], "-h") == 0 || strcmp(argv[0], "--help") == 0))) {
      helpCommand();
      return EXIT_SUCCESS;
   }

   if (sodium_init() < 0) {
      printf("Init failure.\n");
      return EXIT_FAILURE;
   }

   if (strcmp(argv[0], "-ea") == 0 && argc > 2) {
      encryptArchive(argc, argv);
      return EXIT_SUCCESS;
   }

   if (strcmp(argv[0], "-da") == 0 && argc == 3) {
      decryptArchive(argc, argv);
      return EXIT_SUCCESS;
   }

   if (strcmp(argv[0], "-r") == 0 && argc > 1) {
      removeFiles(argc, argv);
      return EXIT_SUCCESS;
   }

   unsigned char salt[saltLength];
   unsigned char key[keyLength];

   std::string filename = argv[1];
   std::string plainText;
   bool freshVault = !std::filesystem::exists(filename);

   if (freshVault) {
      std::string pass;
      setMasterPassword(pass);
      randombytes_buf(salt, saltLength);
      deriveKey(pass, salt, key);
      saveVault(key, "", filename, salt);
   }
   else {
      std::ifstream stream = openFile(filename);
      std::vector<unsigned char> blob = readEncryptedFile(salt, stream);
      std::string masterPassword = readHiddenLine("Input password: ");
      deriveKey(masterPassword, salt, key);
      decryptBlob(key, blob, plainText);
   }

   if (strcmp(argv[0], "-m") == 0 && argc == 2 && !freshVault) {
      resetPassword(plainText, filename);
   }
   else if (strcmp(argv[0], "-v") == 0 && argc == 2) {
      viewFile(plainText);
   }
   else if (strcmp(argv[0], "-e") == 0 && argc == 2) {
      editFile(plainText, filename, salt, key);
   }
   else if (strcmp(argv[0], "-i") == 0 && argc == 2) {
      insertIntoFile(plainText, filename, salt, key);
   }
   else if (strcmp(argv[0], "-d") == 0 && argc == 2) {
      deleteLinesFromFile(plainText, filename, salt, key);
   }
   else if (strcmp(argv[0], "-a") == 0 && argc == 2) {
      addToFile(plainText, filename, salt, key);
   }
   else {
      printf("Invalid command/excess arguments/tried to call '-m' right after creating a fresh vault.\n");
      helpCommand();
   }

   sodium_memzero(&filename[0], filename.size());
   sodium_memzero(&plainText[0], plainText.size());
   sodium_memzero(key, keyLength);
   return EXIT_SUCCESS;
}
