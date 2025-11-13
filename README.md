<!-- ---------------------------------------------------------------- -->
<!-- 🔐 PROJECT HEADER -->
<!-- ---------------------------------------------------------------- -->

<h1 align="center">
  <img src="https://cdn.jsdelivr.net/gh/devicons/devicon/icons/java/java-original.svg" width="60" height="60" alt="Java Logo">
  <img src="https://cdn.jsdelivr.net/gh/devicons/devicon/icons/eclipse/eclipse-original.svg" width="60" height="60" alt="Eclipse IDE Logo">

  <br>
  🔐 <span style="color:#4da6ff">Secure Voting Protocol for Class Elections</span> 🗳️  
</h1>

<h3 align="center">🛡️ A Cryptographically Secure, Anonymous, and Verifiable E-Voting System</h3>

<p align="center">
  <em>Developed as part of the Information Security module — Faculty of Engineering, University of Ruhuna</em>  
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Java-17+-red?logo=openjdk&logoColor=white">
  <img src="https://img.shields.io/badge/Eclipse%20IDE-2023+-purple?logo=eclipseide&logoColor=white">
  <img src="https://img.shields.io/badge/Cryptography-DH%20%7C%20RSA%20%7C%20SHA256-lightblue?logo=lock&logoColor=white">
  <img src="https://img.shields.io/badge/Confidentiality-End%20to%20End-success">
  <img src="https://img.shields.io/badge/License-MIT-lightgrey">
</p>

---

## 🧭 Overview

This project implements a **cryptographically secure electronic voting protocol** designed to guarantee the four essential security properties required in digital elections:

- ✅ **Authentication** – Only legitimate voters can vote  
- 🔐 **Confidentiality** – Votes remain secret  
- 🛡️ **Integrity** – Votes cannot be altered  
- 🕵️ **Anonymity** – Votes cannot be linked to voters  

The protocol operates in two major phases:

1. 🔑 **Authentication Phase**  
2. 🗳️ **Voting Phase**

---

## 🔑 Authentication Phase

### 🧍‍♂️ 1. Voter Login with Nonce

- The voter enters their **username** and generates a one-time random **nonce**.  
- They compute a digest:  

```bash
h(password || nonce)
```
- This digest is sent to the **Election Authority (EA)**.  
- The EA verifies this against stored password hashes.

✅ **Prevents:**  
- Password exposure in plaintext  
- Replay attacks via one-time nonces  
- Impersonation without password knowledge  

---

### 🔄 2. Key Exchange and Token Issuance

- Once authenticated, the EA sends its **Diffie-Hellman (DH) public key** and **RSA-signed certificate** to the voter.  
- The voter verifies the certificate to confirm EA’s identity.  
- The voter then:
  - Generates their own DH key pair  
  - Computes a shared session key `Ks = g^ab mod p`  
  - Creates a **pseudonymous token** (UUID format)  
  - Encrypts the token using the shared key `Ks`  
  - Sends the encrypted token to the EA  

---

### 🖋️ 3. Token Signing by EA

- EA decrypts the token and signs it with its **RSA private key**  
- The signed token is encrypted again using `Ks` and returned to the voter  
- EA records that the voter has been issued a signed token (to prevent multiple voting)

🛡️ **Security Goals Achieved in this Phase:**  
- 🔒 **Confidentiality**: Token is visible only to voter and EA  
- ✅ **Integrity**: Signed token proves no tampering  
- 🔐 **Authentication**: Both voter and EA verify each other  
- 🕵️ **Anonymity**: Token contains no voter-identifiable data  

---

## 🗳️ Voting Phase

### 🧾 1. Vote Commitment

- The voter selects a candidate  
- Computes a **ballot** using:  
  ```bash
  h(vote)
  ```  
  This commits to their choice *without revealing* the vote itself.

---

### 📦 2. Payload Preparation

The voter creates a payload consisting of:  
- 🧮 Ballot hash  
- 🕒 Timestamp  
- 🎟️ Token  
- ✍️ Signed token  

This payload is **encrypted using EA’s RSA public key** and sent securely.

---

### ⚙️ 3. EA Vote Processing

EA decrypts the payload and:  
- ⏱️ Validates the **timestamp** (must be recent)  
- 🔏 Verifies **signature on token** to ensure legitimacy  
- 🚫 Ensures **token is issued only once per voter**  

---

### 🗂️ 4. Ballot Storage

- If valid, the hashed ballot is securely stored  
- No user identity is ever stored with the ballot

---

### 🧮 5. Vote Tallying

- After voting ends, EA compares stored ballot hashes against known candidate name hashes:  
  ```bash
  h("A. Alice"), h("B. Bob"), ...
  ```  
- Votes are counted by matching these hashes

🛡️ **Security Goals Achieved in this Phase:**  
- 🕵️ **Anonymity**: Only ballot hash is stored  
- ✅ **Integrity**: Only valid signed tokens are accepted  
- 🔒 **Confidentiality**: Vote payload is encrypted  
- ⏳ **Freshness**: Timestamp ensures timely votes  

---

## 🧩 System Design Diagram

Below diagram illustrates the **flow of the Secure Voting Protocol** across the Authentication and Voting phases:

<p align="center">
  <img src="img/IS.gif" alt="Secure Voting System" width="750">
</p>

---


<h4 align="center">🗳️ Secure • Anonymous • Verifiable – The Future of Digital Class Elections 🛡️</h4>

<p align="center">
  <img src="https://img.shields.io/badge/Built%20With-Java%20%7C%20Eclipse-blue?logo=java&logoColor=white">
  &nbsp;
  <img src="https://img.shields.io/badge/Security-Diffie--Hellman%20%7C%20RSA%20%7C%20SHA256-green?logo=lock&logoColor=white">
  &nbsp;
  <img src="https://img.shields.io/badge/Protocol-End%20to%20End%20Encrypted-success?logo=shield&logoColor=white">
</p>

