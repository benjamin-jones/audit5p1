5+1 Securty Concept Auditing Framework
======================================

usage: audit5p1.py [-h] [--ssh] [--serial] target username password config

Audit a target with regards to 5+1 security concept

positional arguments:

- target
-- Target for interrogation, ssh: target:port, serial: /dev/ttySX 
- username
-- Username for target
- password
-- Password for user on target
- config
-- Config file to use for target

optional arguments:
  
  -h, --help  show this help message and exit
  
  --ssh       Connect to target with SSH
  
  --serial    Connect to target with Serial
