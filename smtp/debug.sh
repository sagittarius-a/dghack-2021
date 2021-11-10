#!/bin/bash

sudo lsof -t -i tcp:4444 | sudo xargs -I Z kill -9 Z
sudo -E gdb ./dghack2021-smtp-smtpd -ex "set follow-fork-mode child"