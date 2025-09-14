

# the tool

a simple command-line tool written in C++ for hiding and executing an encrypted payload within an image file. It demonstrates a basic steganographic technique for payload delivery and in-memory execution.

## How It Works

1.  **Injection**: The tool encrypts a payload (e.g., shellcode) with a given XOR key and appends it to a host file (like a PNG or JPG). It also appends the payload's size as a footer for easy extraction.
2.  **Execution**: The tool reads the host file, extracts the payload size from the footer, decrypts the payload in memory using the same XOR key, and executes it directly without writing it to disk.

For a more detailed explanation of the techniques used, you can [read the full blog post here](https://portfolio-v2-eight-dusky.vercel.app/blogs/injector).

## Compilation

To compile the tool, you will need a C++ compiler (like `g++`) that supports C++17 for the filesystem library.

```bash
g++ injector.cpp -o injector
```

## Usage

The tool has two modes: **injection** and **execution**.

### To Inject a Payload

```bash
./injector <input_image_path> <output_image_path> <shellcode_path> -key <your_secret_key>
```

**Example:**

```bash
./injector ./media/image.png ./output/new_image.png ./payloads/shellcode.bin -key mysecret
```

### To Execute a Payload

```bash
./injector -execute <image_with_payload> -key <your_secret_key>
```

**Example:**

```bash
./injector -execute ./output/new_image.png -key mysecret
```
