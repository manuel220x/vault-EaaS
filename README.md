### Vault EaaS
Scripts to demostate a use case of Encryption as a Service using Vault.

![Sequence Diagram](https://i.imgur.com/chqagIF.png)


Here the code for the sequence diagram from https://sequencediagram.org:
```
title Vault EaaS



participantgroup #D7FBFF **Network A**
actor Tax Agent
participant client.py
end 
participantgroup #DAFFD7 **Network B**
actor Finance Guy
participant extractor.py
end 
participantgroup #D7FBFF **Network A**
actor Tax Agent2
participant standarize.py
participant workpaper.py
fontawesome f1c3 Excel File
end 
Tax Agent->client.py:Creates encryption keys,\n policy and token with a \nunique clientid
Finance Guy->extractor.py:Using the clientid given\nby the agent the finance\nguy can run the extractor
extractor.py-->Tax Agent2: Data is extracted from ERP system,\nthen the resulting .csv file encrypted\nand sent back to the Agent's storage
Tax Agent2->standarize.py:Agent will run the\ntransformation workflow

standarize.py->workpaper.py:Data is decrypted, transformed and split\ninto multiple encrypted files.
workpaper.py->Excel File:Data is decrypted in memory,\nprocessed and the final artifact\nis created on disk.
```