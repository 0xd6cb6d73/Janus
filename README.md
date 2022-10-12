# Janus

Janus is a pre-build event that performs string obfuscation during compile time. This project is based off the CIA's [Marble Framework](https://wikileaks.org/ciav7p1/cms/space_15204359.html).

*JFK (1991)*

**Bill:** *We're talking about our government here!*

**Jim:** *No, we're talking about a crime, Bill, pure and simple. Y'all better start thinking on a different level, like the CIA does. Now, we're through the looking glass here, people. White is black and black is white.*

This quote is in reference to the CIA having had been in possession of an illegitimate Kaspersky [certificate](https://hive.blog/wikileaks/@fortified/vault-8-or-kaspersky-lab-responds-to-new-wikileaks-analysis-of-fake-ssl-certificates-used-by-the-cia-s-project-hive).  

### Description

Janus is designed to allow for string obfuscation when developing tools. Janus utilizes pre-build and post-build execution steps to apply obfuscation to the tool. If the tool breaks the build, the post-build will always be able to repair it. The pre-build execution step will store clean copies of the code before making modifications. The post-build execution step restores the file to a clean-copy state. 

Janus utilizes the OpenSSL library to perform RSA encryption and Base64 encoding to store the encrypted string/data output within your project in a base64 encoded format. Due to the utilization of RSA, you will be limited in the amount of characters you can encrypt. This is based off the RSA key size. Janus uses a 2048-bit key with OAEP padding, **USE YOUR OWN KEY PAIR**. A 2048-bit key can encrypt up to 214 bytes; (2048/8) – 42 = 256 – 42 = 214 bytes. If you want to encrypt more bytes you will need to use a larger key size. Click [here](https://info.townsendsecurity.com/bid/29195/how-much-data-can-you-encrypt-with-rsa-keys) to read a blog post discussing how much data you can encrypt with RSA keys.

The public and private key are never stored within the binary (at least they shouldn't be). The JanusTester includes the private key as a POC to prove that Janus functions properly. The intended use is to use Janus to encrypt and encode the strings\data and then during runtime retrieve the private key from a server. 

**Janus currently only supports CHAR data type. (No WCHAR or UNICODE support)**

**I will make a YouTube video discussing Janus, Vault 7, and Joshua Schulte next week and will update this README.md with the link. If you are interested in that, make sure to come back and check in if you want to see the video.**

# Terminology 

**Janus:** Janus is the utility that does the encryption, encoding, and altering of source files. Janus scans the project folder looking for any files that contain source, looking for strings and data to scramble. Janus keeps a clean copy of the original source and replaces it with the scrambled versions of strings/data. The source should compile after Janus modifies source.


**Elyashib:** Elyashib restores the source files to their original state. If for any reason, Janus fails or breaks the code, Elyashib can always restore the state to its original.


#  Diagrams

### Compilation Diagram

![](Images/Janus%20Diagram.png)

### Intended Use Diagram

It is recommended to include some form of anti-sandbox techniques to determine if your binary is being analyzed\reverse-engineered in order to withhold the private key being retrieved from the server.

![](Images/Janus%20Intended%20Use.png)

# Setting up Janus Manually

**It is important that the pre-build event be run before any projects are built and the post-build event is ran after all projects are built.**

**Step 1:** Compile Janus and Elyashib

**Step 2:** Add the Janus files to your project (Janus.cpp\Janus.h) located in the JanusTester project. These files will have to be slightly modified because they are currently configured to only work with the JanusTester. (I will make an official header file and update the repository soon).

![](Images/Janus%20Files.PNG)

**Step 3**: Add Janus to the pre-build event of your project

![](Images/Pre-Build%20Event.PNG)

**Step 4:** Add Elyashib to the post-build event of your project

![](Images/Post-Build%20Event.PNG)

**Step 5:** All the best to you

## Video Demonstration

https://user-images.githubusercontent.com/91508682/195268950-83ce5e35-b138-40e7-8a92-0d0f7b254b09.mp4

https://user-images.githubusercontent.com/91508682/195269479-c499b4a2-9280-4e5b-b93e-9f9029249a2c.mp4

## Improvements

* Replace OpenSSL with wolfSSL (this will significantly decrease the final size of the binary)
* Add different encoding methods
* Implement EVP to avoid byte limit 
* Add detection for comments (comments should be ignored in the future)
* Add Unicode support
* Add receipt and validator (will be added soon hopefully)  

## Conclusion

If you found anything of value from this, feel free to share this project, I would greatly appreciate it.

If you have any questions you can add me on Discord: Default#9365

You can donate to my BTC wallet here: 34WFzRRRvscorHsVnLX656rGK4DBWqRKyi
