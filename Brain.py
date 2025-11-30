import hashlib
import random
import string
import time
import sys
# Dependency: pip install bitcoin
from bitcoin import privtopub, pubtoaddr, encode_privkey

# --- File Definitions and Defaults ---
SECRET_FILE = 'Secret.txt'
MATCH_FILE = 'Match.txt'
DEFAULT_PASSWORDS = 1000
DEFAULT_LENGTH = 10

class BrainWalletMatcher:
    def __init__(self):
        self.target_addresses = set()
        self.found_matches = []
        self._load_target_addresses()

    def _load_target_addresses(self):
        """Loads target Bitcoin addresses from Secret.txt into a set."""
        try:
            with open(SECRET_FILE, 'r') as f:
                addresses = [line.strip() for line in f if line.strip()]
                self.target_addresses.update(addresses)
            print(f"✅ Loaded {len(self.target_addresses)} target addresses from {SECRET_FILE}")
        except FileNotFoundError:
            print(f"⚠️ Error: {SECRET_FILE} not found. Please create the file and add target addresses.")
            self.target_addresses = set()
        except Exception as e:
            print(f"Error reading file: {e}")
            self.target_addresses = set()

    def _save_match(self, match_data):
        """Saves the matching wallet details to Match.txt."""
        try:
            with open(MATCH_FILE, 'a') as f:
                f.write("=" * 50 + "\n")
                f.write(f"🎉 MATCH FOUND: {time.ctime()}\n")
                f.write(f"Passphrase: {match_data['passphrase']}\n")
                f.write(f"Matched Address: {match_data['matched_address']}\n")
                f.write(f"Private Key (HEX): {match_data['private_key_hex']}\n")
                f.write(f"Private Key (WIF): {match_data['private_key_wif']}\n")
                f.write(f"P2PKH Address: {match_data['p2pkh_address']}\n")
                f.write("=" * 50 + "\n\n")
        except Exception as e:
            print(f"Error writing match file: {e}")

    def generate_random_password(self, length):
        """Generates a random passphrase (string of characters)."""
        chars = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(chars) for _ in range(length))

    def sha256_hash(self, text):
        """Calculates the SHA256 hash of the text (Brain Wallet core)."""
        return hashlib.sha256(text.encode('utf-8')).hexdigest()

    def generate_bitcoin_addresses(self, passphrase):
        """Generates Bitcoin keypair and addresses (P2PKH) from the passphrase."""
        private_key_hex = self.sha256_hash(passphrase)
        privkey = private_key_hex
        
        try:
            # P2PKH generation process (starts with '1')
            public_key_compressed = privtopub(privkey)
            p2pkh_address = pubtoaddr(public_key_compressed)
            wif_format = encode_privkey(privkey, 'wif')
            
            addresses_to_check = {p2pkh_address}
            
            return {
                'passphrase': passphrase,
                'private_key_hex': private_key_hex,
                'private_key_wif': wif_format,
                'p2pkh_address': p2pkh_address,
                'addresses_to_check': addresses_to_check
            }
        except Exception:
            # Handles mathematically invalid keys from SHA256 output
            return None

    def _display_attempt_info(self, data, is_matched):
        """Displays the generated keys and the comparison result directly to the console."""
        
        status = "💰 MATCH!" if is_matched else "❌ NO MATCH"
        
        # 🌟 التعديل هنا لعرض المفتاح كاملاً (64 رمزاً) 🌟
        key_display = data['private_key_hex']
        
        output_line = (
            f"[{status:<10}] "
            f"Pass: {data['passphrase']:<15} "
            f"| Key (HEX): {key_display} " # لم يعد هناك قطع '...'
            f"| Addr (P2PKH): {data['p2pkh_address']} "
        )
        
        print(output_line)

    def process_passphrase(self, passphrase):
        """Processes a single passphrase, performs local comparison, and displays results."""
        
        if not self.target_addresses:
             return None
             
        keypair_data = self.generate_bitcoin_addresses(passphrase)
        if not keypair_data:
            return None
        
        is_matched = False
        
        # --- Local Comparison Step ---
        for generated_addr in keypair_data['addresses_to_check']:
            if generated_addr in self.target_addresses:
                keypair_data['matched_address'] = generated_addr
                self._save_match(keypair_data)
                self.found_matches.append(keypair_data)
                is_matched = True
                break
        
        # Display keys and comparison result on PowerShell
        self._display_attempt_info(keypair_data, is_matched)
        
        return keypair_data

    def auto_mode(self, num_passwords, password_length):
        """Automatic mode to generate and match random passphrases."""
        print("=" * 80)
        print("Bitcoin BrainWallet Local Matcher - Auto Mode")
        print("=" * 80)
        print(f"Targeting {len(self.target_addresses)} addresses in {SECRET_FILE}.")
        print(f"Passphrase Length: {password_length} | Total Attempts: {num_passwords}")
        print("-" * 80)
        
        start_time = time.time()
        
        for i in range(num_passwords):
            passphrase = self.generate_random_password(password_length)
            self.process_passphrase(passphrase)

        # Final progress report
        elapsed = time.time() - start_time
        per_second = num_passwords / elapsed if elapsed > 0 else 0
        
        print("\n" + "=" * 80)
        print(f"Scan finished. Total checked: {num_passwords} in {elapsed:.2f}s.")
        print(f"Average rate: {per_second:.2f} passphrases per second.")
        print(f"Total Matches Found: {len(self.found_matches)}")
        print(f"Results saved to {MATCH_FILE}")
        print("=" * 80)

# --- Entry Point ---
def main():
    matcher = BrainWalletMatcher()
    
    if not matcher.target_addresses:
        print("\nExiting. Please populate Secret.txt with target addresses.")
        return

    print("\n--- BrainWallet Matcher Configuration ---")
    
    try:
        num_passwords_input = input(f"Number of random passphrases to test (default: {DEFAULT_PASSWORDS}): ").strip()
        num_passwords = int(num_passwords_input) if num_passwords_input else DEFAULT_PASSWORDS
        
        password_length_input = input(f"Passphrase length (number of characters, default: {DEFAULT_LENGTH}): ").strip()
        password_length = int(password_length_input) if password_length_input else DEFAULT_LENGTH
        
        if num_passwords <= 0 or password_length <= 0:
            raise ValueError
        
        matcher.auto_mode(num_passwords, password_length)
        
    except ValueError:
        print("Invalid input. Please enter a positive integer for count and length.")
    except KeyboardInterrupt:
        print("\n\nProgram interrupted by user. Final results are saved.")

if __name__ == "__main__":
    main()