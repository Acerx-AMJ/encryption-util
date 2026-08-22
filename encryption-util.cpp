#include "sodium.h" // IWYU pragma: export
#include <algorithm>
#include <cstring>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>

constexpr size_t keyLength = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
constexpr size_t saltLength = crypto_pwhash_SALTBYTES;
constexpr const char *defaultPasswordFile = "passwords";

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

std::string readHiddenLine() {
   setEcho(false);
   std::string line;
   std::getline(std::cin >> std::ws, line);
   setEcho(true);
#ifndef _WIN32
   printf("\n");
#endif
   return line;
}

void splitInPlace(std::vector<std::string> &output, const std::string &string, char delimiter) {
   size_t delimiterCount = std::count(string.begin(), string.end(), delimiter);
   output.reserve(output.size() + delimiterCount + 1);

   std::stringstream stream (string);
   std::string piece;

   while (std::getline(stream, piece, delimiter)) {
      output.push_back(piece);
   }
}

bool setMasterPassword(std::string &outPass) {
   std::string pass1;
   printf("New password: ");
   pass1 = readHiddenLine();

   std::string pass2;
   printf("Confirm password: ");
   pass2 = readHiddenLine();

   if (pass1 != pass2) {
      printf("Passwords do not match. Try again.\n");
      sodium_memzero(&pass1[0], pass1.size());
      sodium_memzero(&pass2[0], pass2.size());
      return setMasterPassword(outPass);
   }
   outPass = pass1;
   sodium_memzero(&pass1[0], pass1.size());
   sodium_memzero(&pass2[0], pass2.size());
   return true;
}

bool deriveKey(const std::string &password, const unsigned char *salt, unsigned char *outKey) {
   return crypto_pwhash(outKey, keyLength, password.c_str(), password.size(), salt, crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE, crypto_pwhash_ALG_ARGON2ID13) == 0;
}

bool encryptBlob(const unsigned char *key, const std::string &plaintext, std::vector<unsigned char> &out) {
   unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
   randombytes_buf(nonce, sizeof nonce);
   out.resize(sizeof nonce + plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
   memcpy(out.data(), nonce, sizeof nonce);

   unsigned long long ciphertext_len;
   crypto_aead_xchacha20poly1305_ietf_encrypt(out.data() + sizeof nonce, &ciphertext_len, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size(), nullptr, 0, nullptr, nonce, key);
   out.resize(sizeof nonce + ciphertext_len);
   return true;
}

bool decryptBlob(const unsigned char *key, const std::vector<unsigned char> &in, std::string &plaintext) {
   constexpr size_t NB = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
   if (in.size() < NB + crypto_aead_xchacha20poly1305_ietf_ABYTES) return false;

   const unsigned char *nonce = in.data();
   const unsigned char *ciphertext = in.data() + NB;
   unsigned long long ciphertext_len = in.size() - NB;
   std::vector<unsigned char> out(ciphertext_len);
   unsigned long long out_len;

   if (crypto_aead_xchacha20poly1305_ietf_decrypt(out.data(), &out_len, nullptr, ciphertext, ciphertext_len, nullptr, 0, nonce, key) != 0) {
      return false;
   }
   plaintext.assign(out.begin(), out.begin() + out_len);
   return true;
}

void saveVault(const unsigned char *key, const std::string &plaintext, const std::string &filename, const unsigned char *salt) {
   std::vector<unsigned char> out;
   encryptBlob(key, plaintext, out);
   std::ofstream pf(filename, std::ios::binary | std::ios::trunc);
   pf.write(reinterpret_cast<const char*>(salt), saltLength);
   pf.write(reinterpret_cast<char*>(out.data()), out.size());
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

int main(int argc, char *argv[]) {
   if (argc < 2 || (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
      printf("password-manager\n");
      printf("Usage:\n\t./password-manager [ARG]\n");
      printf("Args:\n");
      printf("\t-h                       show help.\n");
      printf("\t-m  [file?]              reset master password.\n");
      printf("\t-v  [file?]              view.\n");
      printf("\t-e  [file?]              edit.\n");
      printf("\t-i  [file?]              insert.\n");
      printf("\t-d  [file?]              delete.\n");
      printf("\t-a  [file?]              add.\n");
      printf("\t-ef [in] [out]           encrypt a file.\n");
      printf("\t-df [in] [out]           decrypt a file.\n");
      printf("\t-ea [in1,in2,...] [out]  combine files/directories into an encrypted archive.\n");
      printf("\t-da [in] [out]           decrypt an archive.\n");
      return EXIT_SUCCESS;
   }

   if (sodium_init() < 0) {
      printf("Init failure.\n");
      return EXIT_FAILURE;
   }

   if (strcmp(argv[1], "-ef") == 0 && argc == 4) {
      unsigned char salt[saltLength];
      unsigned char key[keyLength];
      std::string pass;
      setMasterPassword(pass);
      randombytes_buf(salt, sizeof salt);
      if (!deriveKey(pass, salt, key)) {
         printf("Key derivation failed.\n");
         return EXIT_FAILURE;
      }
      sodium_memzero(&pass[0], pass.size());
      std::ifstream pf (argv[2], std::ios::binary);
      if (!pf.is_open()) {
         printf("Could not open '%s'.\n", argv[2]);
         return EXIT_FAILURE;
      }
      std::string plainText {std::istreambuf_iterator<char>(pf), std::istreambuf_iterator<char>()};
      saveVault(key, plainText, argv[3], salt);
      sodium_memzero(&plainText[0], plainText.size());
      sodium_memzero(key, sizeof key);
      printf("Encryption complete.\n");
      return EXIT_SUCCESS;
   }

   if (strcmp(argv[1], "-df") == 0 && argc == 4) {
      std::ifstream pf(argv[2], std::ios::binary);
      if (!pf.is_open()) {
         printf("Could not open '%s'.\n", argv[2]);
         return EXIT_FAILURE;
      }
      unsigned char salt[saltLength];
      unsigned char key[keyLength];
      pf.read(reinterpret_cast<char*>(salt), sizeof salt);
      std::vector<unsigned char> blob((std::istreambuf_iterator<char>(pf)), {});
      pf.close();
      std::string plainText, masterPassword;
      printf("Input password: ");
      masterPassword = readHiddenLine();
      if (!deriveKey(masterPassword, salt, key)) {
         printf("Key derivation failed.\n");
         return EXIT_FAILURE;
      }
      sodium_memzero(&masterPassword[0], masterPassword.size());
      if (!decryptBlob(key, blob, plainText)) {
         printf("Invalid password.\n");
         sodium_memzero(key, sizeof key);
         return EXIT_FAILURE;
      }
      std::ofstream out(argv[3], std::ios::binary | std::ios::trunc);
      out.write(plainText.data(), plainText.size());
      sodium_memzero(&plainText[0], plainText.size());
      sodium_memzero(key, sizeof key);
      printf("Decryption complete.\n");
      return EXIT_SUCCESS;
   }

   if (strcmp(argv[1], "-ea") == 0 && argc > 3) {
      unsigned char salt[saltLength];
      unsigned char key[keyLength];
      std::string pass;
      setMasterPassword(pass);
      randombytes_buf(salt, sizeof salt);
      if (!deriveKey(pass, salt, key)) {
         printf("Key derivation failed.\n");
         return EXIT_FAILURE;
      }
      sodium_memzero(&pass[0], pass.size());
      std::string plainText;
      for (int i = 2; i < argc - 1; ++i) {
         std::string path = argv[i];
         if (!std::filesystem::exists(path)) {
            printf("File '%s' does not exist.\n", path.c_str());
            continue;
         }

         if (std::filesystem::is_directory(path)) {
            for (const auto &file: std::filesystem::recursive_directory_iterator(path)) {
               if (!file.is_regular_file()) continue;
               std::string path = file.path().string();
               std::ifstream pf (path, std::ios::binary);
               if (!pf.is_open()) {
                  printf("Could not open '%s'.\n", path.c_str());
                  continue;
               }
               std::string contents {std::istreambuf_iterator<char>(pf), std::istreambuf_iterator<char>()};
               plainText.reserve(plainText.size() + path.size() + contents.size() + sizeof(uint64_t) * 2);
               appendU64(plainText, path.size());
               plainText += path;
               appendU64(plainText, contents.size());
               plainText += contents;
               sodium_memzero(&path[0], path.size());
               sodium_memzero(&contents[0], contents.size());
            }
         }
         else if (std::filesystem::is_regular_file(path)) {
            std::ifstream pf (path, std::ios::binary);
            if (!pf.is_open()) {
               printf("Could not open '%s'.\n", path.c_str());
               continue;
            }
            std::string contents {std::istreambuf_iterator<char>(pf), std::istreambuf_iterator<char>()};
            plainText.reserve(plainText.size() + path.size() + contents.size() + sizeof(uint64_t) * 2);
            appendU64(plainText, path.size());
            plainText += path;
            appendU64(plainText, contents.size());
            plainText += contents;
            sodium_memzero(&path[0], path.size());
            sodium_memzero(&contents[0], contents.size());
         }
         sodium_memzero(&path[0], path.size());
      }
      saveVault(key, plainText, argv[argc-1], salt);
      sodium_memzero(&plainText[0], plainText.size());
      sodium_memzero(key, sizeof key);
      printf("Encryption complete.\n");
      return EXIT_SUCCESS;
   }

   if (strcmp(argv[1], "-da") == 0 && argc == 4) {
      std::ifstream pf(argv[2], std::ios::binary);
      if (!pf.is_open()) {
         printf("Could not open %s.\n", argv[2]);
         return EXIT_FAILURE;
      }
      unsigned char salt[saltLength];
      unsigned char key[keyLength];
      pf.read(reinterpret_cast<char*>(salt), sizeof salt);
      std::vector<unsigned char> blob((std::istreambuf_iterator<char>(pf)), {});
      pf.close();
      std::string plainText, masterPassword;
      printf("Input password: ");
      masterPassword = readHiddenLine();
      if (!deriveKey(masterPassword, salt, key)) {
         printf("Key derivation failed.\n");
         return EXIT_FAILURE;
      }
      sodium_memzero(&masterPassword[0], masterPassword.size());
      if (!decryptBlob(key, blob, plainText)) {
         printf("Invalid password.\n");
         sodium_memzero(key, sizeof key);
         return EXIT_FAILURE;
      }
      size_t pos = 0;
      while (pos < plainText.size()) {
         uint64_t nameLen;
         if (!readU64(plainText, pos, nameLen) || pos + nameLen > plainText.size()) {
            printf("Corrupted archive (bad path entry).\n");
            sodium_memzero(&plainText[0], plainText.size());
            return EXIT_FAILURE;
         }
         std::string rel = plainText.substr(pos, nameLen);
         pos += nameLen;
   
         uint64_t dataLen;
         if (!readU64(plainText, pos, dataLen) || pos + dataLen > plainText.size()) {
            printf("Corrupted archive (bad data entry).\n");
            sodium_memzero(&rel[0], rel.size());
            sodium_memzero(&plainText[0], plainText.size());
            return EXIT_FAILURE;
         }
   
         std::filesystem::path outPath = std::filesystem::path(argv[3]) / rel;
         std::filesystem::create_directories(outPath.parent_path());
         std::ofstream out(outPath, std::ios::binary | std::ios::trunc);
         out.write(plainText.data() + pos, dataLen);
         pos += dataLen;
         sodium_memzero(&rel[0], rel.size());
      }
      sodium_memzero(&plainText[0], plainText.size());
      sodium_memzero(key, sizeof key);
      printf("Decryption complete.\n");
      return EXIT_SUCCESS;
   }

   unsigned char salt[saltLength];
   unsigned char key[keyLength];

   std::string filename = (argc == 3 ? argv[2] : defaultPasswordFile);
   std::string plainText;
   bool freshVault = !std::filesystem::exists(filename);

   if (freshVault) {
      std::string pass;
      setMasterPassword(pass);
      randombytes_buf(salt, sizeof salt);
      if (!deriveKey(pass, salt, key)) {
         printf("Key derivation failed.\n");
         sodium_memzero(key, sizeof key);
         return EXIT_FAILURE;
      }
      sodium_memzero(&pass[0], pass.size());
      saveVault(key, "", filename, salt);
   }
   else {
      std::ifstream pf(filename, std::ios::binary);
      if (!pf.is_open()) {
         printf("Could not open %s.\n", filename.c_str());
         return EXIT_FAILURE;
      }

      pf.read(reinterpret_cast<char*>(salt), sizeof salt);
      std::vector<unsigned char> blob((std::istreambuf_iterator<char>(pf)), {});
      pf.close();

      std::string masterPassword;
      printf("Input password: ");
      masterPassword = readHiddenLine();

      if (!deriveKey(masterPassword, salt, key)) {
         printf("Key derivation failed.\n");
         return EXIT_FAILURE;
      }
      sodium_memzero(&masterPassword[0], masterPassword.size());

      if (!decryptBlob(key, blob, plainText)) {
         printf("Invalid password.\n");
         sodium_memzero(key, sizeof key);
         return EXIT_FAILURE;
      }
   }

   if (strcmp(argv[1], "-m") == 0 && !freshVault) {
      std::string newPass;
      setMasterPassword(newPass);

      unsigned char newSalt[saltLength];
      unsigned char newKey[keyLength];
      randombytes_buf(newSalt, sizeof newSalt);

      if (!deriveKey(newPass, newSalt, newKey)) {
         printf("Key derivation failed.\n");
         sodium_memzero(key, sizeof key);
         return EXIT_FAILURE;
      }
      sodium_memzero(&newPass[0], newPass.size());

      saveVault(newKey, plainText, filename, newSalt);
      sodium_memzero(newKey, sizeof newKey);
   }

   if (strcmp(argv[1], "-v") == 0) {
      printf("%s", plainText.c_str());
   }

   if (strcmp(argv[1], "-e") == 0) {
      std::vector<std::string> lines;
      splitInPlace(lines, plainText, '\n');
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

   if (strcmp(argv[1], "-i") == 0) {
      std::vector<std::string> lines;
      splitInPlace(lines, plainText, '\n');
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

   if (strcmp(argv[1], "-d") == 0) {
      std::vector<std::string> lines;
      splitInPlace(lines, plainText, '\n');
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

   if (strcmp(argv[1], "-a") == 0) {
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

   sodium_memzero(&plainText[0], plainText.size());
   sodium_memzero(key, sizeof key);
   return EXIT_SUCCESS;
}
