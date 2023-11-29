# RSA Encryption Project

    Academic Project written for Concepts of Parallel and Distributed Systems(CSCI-251).

## Description

    A program that sends secure messages using RSA keys.
    Prime numbers are generated using code from the previous project for this class.
    All code will be written in C# and using the .NET framework.

## Authors

    - Damon B. Gonzalez

## Plan

    - Implement Command Line Argument parsing
    - Use existing C# class to interface with the server
    - Implement rsa formula
    - Implement each command line argument option as runnable portion of the program

### Testing with curl

    The url to the server is "http://kayrun.cs.rit.edu:5000".

     GET http://kayrun.cs.rit.edu:5000/Message/email
     PUT http://kayrun.cs.rit.edu:5000/Message/email (with json body)
     GET http://kayrun.cs.rit.edu:5000/Key/email
     PUT http://kayrun.cs.rit.edu:5000/Key/email (with json body)

    To get the key of any person on the server execute the following on the command line

        'curl http://kayrun.cs.rit.edu:5000/Key/<the persons' email>'