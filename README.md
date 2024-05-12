# Tinyshell Decipher

Work in progress.

## how to build

use the VSCode folder, or if you want to build it manually, simply

```sh
gcc -g *.c -o myApp
```

## how to use

First, extract the traffic into two files, the client.bin, and the server.bin. They must be
ascii hex, one linebreak per transmission. Will be revised in the future

Once you have those two files, you can simply give it the files in this order
```sh
./myApp client.bin server.bin
```

## Will there be more work?

In the future. if things dont get too out of hand. I want to get this polished.