"""
SAFE Ransomware Simulator for Testing
⚠️ This does NOT perform real encryption - it's for testing detection only
"""
import os
import time
import random
import argparse


def simulate_encryption_attack(target_dir, num_files=10, delay=0.5):
    """
    Simulate ransomware by renaming files with .encrypted extension
    
    Args:
        target_dir: Directory to target
        num_files: Number of files to "encrypt"
        delay: Delay between operations (seconds)
    """
    print(f"\n🧪 Starting SIMULATED ransomware attack...")
    print(f"Target: {target_dir}")
    print(f"Files to encrypt: {num_files}")
    print(f"Delay: {delay}s between files\n")
    
    files_encrypted = 0
    
    for root, dirs, files in os.walk(target_dir):
        for file in files:
            if files_encrypted >= num_files:
                break
            
            file_path = os.path.join(root, file)
            
            # Skip if already "encrypted"
            if file.endswith('.encrypted'):
                continue
            
            # Simulate encryption by renaming
            encrypted_path = file_path + '.encrypted'
            
            try:
                # Write some random bytes to simulate encrypted content
                with open(file_path, 'rb') as f:
                    original_content = f.read()
                
                # Write random-looking data
                with open(encrypted_path, 'wb') as f:
                    random_data = bytes([random.randint(0, 255) for _ in range(len(original_content) if original_content else 100)])
                    f.write(random_data)
                
                # Remove original
                os.remove(file_path)
                
                print(f"✓ Encrypted: {file} -> {os.path.basename(encrypted_path)}")
                files_encrypted += 1
                
                time.sleep(delay)
                
            except Exception as e:
                print(f"✗ Failed to encrypt {file}: {e}")
        
        if files_encrypted >= num_files:
            break
    
    print(f"\n🎯 Attack complete! {files_encrypted} files encrypted.")
    print(f"💀 Your files are now 'encrypted'!\n")


def create_test_files(target_dir, num_files=15):
    """Create test files for the simulation"""
    os.makedirs(target_dir, exist_ok=True)
    
    print(f"📝 Creating {num_files} test files in {target_dir}...")
    
    for i in range(num_files):
        filename = f"document_{i+1}.txt"
        filepath = os.path.join(target_dir, filename)
        
        with open(filepath, 'w') as f:
            f.write(f"This is test document #{i+1}\n")
            f.write(f"Created for ransomware detection testing.\n")
            f.write(f"Content: {random.choice(['Important', 'Critical', 'Secret'])} data\n")
    
    print(f"✅ Created {num_files} test files.\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Simulate ransomware for testing')
    parser.add_argument('--target', default='./protected_data', help='Target directory')
    parser.add_argument('--files', type=int, default=10, help='Number of files to encrypt')
    parser.add_argument('--delay', type=float, default=0.5, help='Delay between operations')
    parser.add_argument('--create-test-files', action='store_true', help='Create test files first')
    
    args = parser.parse_args()
    
    if args.create_test_files:
        create_test_files(args.target, num_files=15)
    
    print("\n" + "="*60)
    print("⚠️  WARNING: This is a SIMULATED attack for testing only!")
    print("="*60)
    
    input("Press Enter to start the simulated attack...")
    
    simulate_encryption_attack(args.target, args.files, args.delay)