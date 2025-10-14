# Argument parsing and quoting

Passing strings vs integers:
```bash
# pass "12345678" (string) instead of 12345678 (int)
osc-cli icu CreateAccount   --Email "example@email.com" --FirstName "Osc" --LastName "Cli" --Password "12345toto"   --ZipCode '"92000"'   --Country "France"   --CustomerId '"12345678"'
```

Arrays of strings:
```bash
osc-cli api CreateDhcpOptions --DomainName="toot.toot" --DomainNameServers="['1.1.1.1']" --NtpServers="['1.1.1.1']"
```

Complex structures:
```bash
osc-cli icu CreateListenerRule --Instances '[{"InstanceId": "i-12345678"}]' --ListenerDescription '{"LoadBalancerName": "osc", "LoadBalancerPort": 80}' --ListenerRuleDescription '{"RuleName": "hello", "Priority": 100, "PathPattern": "/"}'
```

Type hints:
```bash
osc-cli api example --obj=[1,2]     # list
osc-cli api example --obj=10        # int
osc-cli api example --obj="10"      # int
osc-cli api example --obj="'10'"    # str
osc-cli api example --obj=\"10\"    # str

osc-cli api example --obj="hello"   # str
osc-cli api example --obj=hello     # str
# If your list contains strings with special characters:
osc-cli api example --obj="['vol-12345678', 'vol-87654322']"  # list
```
