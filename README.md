# Quantum-Tunneling-Security-Reloaded
Programm with multiple privacy and security tools

Remasterd GUI based version of [Quantum-Tunneling-Security](https://github.com/Eisblume-2000/Quantum-Tunneling-Security)

## Features (as of Version 1.0)

* Text-Encryption/Decryption
* Password-Generator
* File-Encryption/Decryption
* Zip-File-Scanner
* One-Time-Decryption

## Planned Features

* Encrypted-Local-Chat

## Text-Encryption/Decryption

* Takes a message, a password and a salt to encrypt/decrypt the message
  ![Text-Encryption/Decryption](img/Text-EncryptionDecryption.JPG)
* The encrypted/decrypted message will then be displayed

## Password-Generator

* The Generator can generate passwords with any lengths
  ![Password-Generator](img/Password-Generator.JPG)
* The Generator uses one of two API's to request numbers and then uses these to generate a password, with the help of character dictionary
  * All passwords will have at least one:
    * Small letter
    * Big letter
    * Number
    * Special character
  * Due to the use of API's this feature needs an Internet connection
  
## File-Encryption/Decryption

* Takes a file, a password and a salt to encrypt/decrypt the file
  ![File-Encryption/Decryption](img/File-EncryptionDecryption.JPG)
* The encrypted/decrypted file will be written to the specified standared output directory

## Zip-File-Scanner

* This feature takes a Zipfile and gets the size of the unpacked files
  ![Zip-File-Scanner](img/Zip-File-Scanner.JPG)
* It displays the size of the unpacked files aswell as the ratio of size to the Zipfile itself, if a certain threshold is passed it will display a warning
  * This tool is especially usefull to find Zipbombs
    * [Zipbombs, for testing purposes, can be found here](https://www.bamsoftware.com/hacks/zipbomb/)
    
 ## One-Time-Decryption
 
 * Takes a file, a password and a salt and decrypts the file
  ![One-Time-Decryption](img/Text-EncryptionDecryption.JPG)
 * The decrypted file will not be written to the standared output directory, but instead displayed in the programm(currently only for .txt files)
 
 ## Additional features/infos
 
 * Option to change the standared output directory
 * The programm creates a folder at "C:\ProgramData\Quantum-Tunneling-Security-Reloaded"
 
 ## TODO list
 
 * Make it so that encrypted/decrypted files keep their names
 * Add the Encrypted-Local-Chat
 * Change it so spaces can't appear in generated passwords
 * Fix bugs
 * Improve my grammar and spelling (English isn't my native language)
 * Add crashlog feature
 
 ## Issues
 
 * Pls report issues [here](https://github.com/Eisblume-2000/Quantum-Tunneling-Security-Reloaded/issues)
  * Pls state how you encountered the issue
  * Pls include log files (if i add this feature)
