## 1. Correctness

Assume a message byte $m_i$ is encrypted using key byte $k_{i \bmod \ell}$.

Encryption gives

$$
c_i = m_i \oplus k_{i \bmod \ell}.
$$

Decryption XORs the ciphertext with the same key byte:

$$
m_i' = c_i \oplus k_{i \bmod \ell}.
$$

Substitute the encryption equation:

$$
m_i'
=
(m_i \oplus k_{i \bmod \ell})
\oplus
k_{i \bmod \ell}.
$$

Using associativity of XOR,

$$
m_i'
=
m_i
\oplus
(k_{i \bmod \ell} \oplus k_{i \bmod \ell}).
$$

Since $x \oplus x = 0$ and $x \oplus 0 = x$,

$$
m_i' = m_i.
$$

Therefore, every decrypted byte equals the corresponding plaintext byte, so

$$
\mathsf{Dec}_k(\mathsf{Enc}_k(m)) = m.
$$

This holds for any message length because $i \bmod \ell$ selects the correct repeating key byte at every position. If the message is empty, there are no bytes to process, so encryption and decryption both return the empty message.

## 2. Known Plaintext

Assume the attacker knows plaintext byte $m_i$ and the corresponding ciphertext byte $c_i$.

Encryption gives

$$
c_i = m_i \oplus k_{i \bmod \ell}.
$$

XOR both sides with $m_i$:

$$
m_i \oplus c_i
=
m_i \oplus m_i \oplus k_{i \bmod \ell}.
$$

Since $m_i \oplus m_i = 0$,

$$
k_{i \bmod \ell} = m_i \oplus c_i.
$$

Therefore, the attacker learns the key byte used at position $i$.

Because the key repeats every $\ell$ bytes, the same key byte is used at every position

$$
j \equiv i \pmod{\ell}.
$$

That is, at positions

$$
i,\ i+\ell,\ i+2\ell,\ldots
$$

within the message. The attacker can therefore decrypt the ciphertext bytes at all of those positions using the recovered key byte.

## 3. Key Reuse

Assume two equal-length messages $m$ and $m'$ are encrypted using the same repeating key, starting at key position zero.

For position $i$,

$$
c_i = m_i \oplus k_{i \bmod \ell}
$$

and

$$
c_i' = m_i' \oplus k_{i \bmod \ell}.
$$

XOR the two ciphertext bytes:

$$
c_i \oplus c_i'
=
(m_i \oplus k_{i \bmod \ell})
\oplus
(m_i' \oplus k_{i \bmod \ell}).
$$

Rearranging the terms gives

$$
c_i \oplus c_i'
=
m_i \oplus m_i'
\oplus
(k_{i \bmod \ell} \oplus k_{i \bmod \ell}).
$$

Since

$$
k_{i \bmod \ell} \oplus k_{i \bmod \ell} = 0,
$$

the key cancels:

$$
c_i \oplus c_i' = m_i \oplus m_i'.
$$

Therefore, reusing the same key reveals the XOR of the two plaintext bytes.

This does **not** immediately reveal either $m_i$ or $m_i'$ by itself. However, it removes the key from the equation and exposes a relationship between the two plaintexts. If an attacker knows or correctly guesses one plaintext byte, the other can be recovered:

$$
m_i' = m_i \oplus c_i \oplus c_i'.
$$

Key reuse therefore leaks information about the messages even when the key itself is not directly recovered.

## 4. One-Time Pad Comparison

A one-time pad requires:

- the key to be shared securely between the sender and receiver;
- the key to be chosen uniformly at random;
- the key to be at least as long as the message; and
- the key to be used only once.

For a message of length $n$, encryption is

$$
c_i = m_i \oplus k_i.
$$

If repeating-key XOR uses a key of length $\ell<n$, then

$$
k_i = k_{i \bmod \ell}.
$$

This means the same key bytes are reused within the message. The scheme therefore violates the one-time pad **length** and **single-use** conditions.

If the same key is reused across multiple messages, the **single-use** condition is also violated. For two ciphertexts,

$$
c_i = m_i \oplus k_i
$$

and

$$
c_i' = m_i' \oplus k_i,
$$

so

$$
c_i \oplus c_i' = m_i \oplus m_i'.
$$

The key cancels, revealing a relationship between the two plaintexts.

Therefore, repeating-key XOR is not a one-time pad when the key repeats within a message or is reused across messages.

## 5. Security Limits

### (a) Short repeating key

If the key has length $\ell<n$, then the same key bytes are reused:

$$
c_i = m_i \oplus k_{i \bmod \ell}.
$$

This does not provide strong confidentiality because the repetition creates patterns in the ciphertext. An attacker can group positions that use the same key byte and use known plaintext, frequency information, or other message structure to learn information about the plaintext or key.

### (b) Random key at least as long as the message

If the key is uniformly random, at least as long as the message, and never reused, then each message byte is XORed with a fresh random key byte:

$$
c_i = m_i \oplus k_i.
$$

Under these conditions, the construction provides the confidentiality of a one-time pad.

However, it does not provide integrity or authenticity. An attacker can modify a ciphertext byte:

$$
c_i' = c_i \oplus \Delta
$$

which causes the decrypted byte to become

$$
m_i' = m_i \oplus \Delta.
$$

The receiver has no way to determine from the ciphertext alone whether this modification occurred.

Secure key distribution is also necessary. The sender and receiver must share the random key secretly; anyone who obtains the key can decrypt the message.

## Sources
In-Class Slides as well as University of Maryland — Jonathan Katz, CMSC 456
https://www.cs.umd.edu/~jkatz/crypto/s22/lectures.html

Boneh & Shoup Applied Cryptography Textboof Online pdf
Pages 6-12

Stanford CS255 — Many-Time Pad exercise
https://cs255.stanford.edu/hw/hw1.html