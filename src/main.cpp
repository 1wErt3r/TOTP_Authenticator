#include <iostream>
#include <string>
#include <vector>
#include <cstdio>
#include <cstdlib>

#include "totp.h"
#include "storage.h"

using namespace std;

static void showHelp() {
    cout << "TOTP Authenticator" << endl;
    cout << "Usage:" << endl;
    cout << "  totp add <name> <secret> - Add a new account" << endl;
    cout << "  totp list - List all accounts" << endl;
    cout << "  totp generate <name> - Generate code for account" << endl;
    cout << "  totp delete <name> - Remove an account" << endl;
    cout << "  totp help - Show this help" << endl;
}

int main(int argc, char* argv[]) {
    try {
        TOTPStorage storage;

        if (argc < 2) {
            cout << "[DEBUG] Not enough arguments (argc < 2)" << endl;
            showHelp();
            return 1;
        }

        std::string command = argv[1];
        cout << "[DEBUG] Command: '" << command << "', argc: " << argc << endl;

        if (command == "add" && argc == 4) {
            cout << "[DEBUG] Processing 'add' command" << endl;
            TOTPAccount account;
            account.name = argv[2];
            account.secret = argv[3];
            account.digits = 6;
            account.period = 30;
            account.issuer = "Added via CLI";

            cout << "[DEBUG] Attempting to add account: " << account.name << endl;
            if (storage.addAccount(account)) {
                cout << "Account added: " << account.name << endl;
            } else {
                cerr << "Failed to add account: " << account.name << endl;
                return 1;
            }
        }
        else if (command == "list") {
            auto accounts = storage.listAccounts();
            if (accounts.empty()) {
                cout << "No accounts stored." << endl;
            } else {
                cout << "Stored accounts:" << endl;
                for (const auto& acc : accounts) {
                    cout << "- " << acc.name << " (Secret: " << acc.secret << ")" << endl;
                }
            }
        }
        else if (command == "generate" && argc == 3) {
            try {
                TOTPAccount account = storage.getAccount(argv[2]);
                TOTP generator(account.secret, account.digits, account.period);
                cout << "Code: " << generator.generateCode() << endl;
            } catch (const exception& e) {
                cerr << "Error: " << e.what() << endl;
                return 1;
            }
        }
        else if (command == "delete" && argc == 3) {
            if (storage.deleteAccount(argv[2])) {
                cout << "Account removed: " << argv[2] << endl;
            } else {
                cerr << "Account not found!" << endl;
                return 1;
            }
        }
        else {
            cout << "[DEBUG] Command not recognized or incorrect number of arguments" << endl;
            showHelp();
        }
    } catch (const std::exception& e) {
        cerr << "Fatal error: " << e.what() << endl;
        return 1;
    }

    return 0;
}
