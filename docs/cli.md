# Interactive usage

```bash
$ sharedvault secrets.svlt
* login USER - Logs in as an existing user to manipulate secrets
* invite - Creates a new user
* who [PATTERN] - Lists all users whose name matches the regex
* what [PATTERN] - Lists all secrets whose title matchees the regex
```

```bash
> login dorian
password: 

* logout - Drops privileges of the user `dorian`
* invite - Creates a new user
* new - Create a new secret
* who [PATTERN] - Lists all users whose name matches the regex
* what [PATTERN] - Lists all secrets whose title matchees the regex
* explain TITLE - Explain how a secret can be opened
* open TITLE - Opens a secret
* grant USER POSITION TITLE - Allow someone to open a secret

dorian> 
```

```bash
> invite
Username: zaya
User type:
* Password - User keys are stored in this file. Less secure but more convenient.
* External - User is responsible for storing their own keys.
* Yubikey - User keys are stored on a trusted device.

> Password
password: 

> External
Public key: ....

> Yubikey
Not supported yet :(
```

```bash
> who
Type     | User
---------|-----
Password | dorian
External | zaya
Password | aline
```

```bash
> what
Open | Title  
-----|------
1/1  | My super secret
0/1  | Zaya's secret
2/3  | Our shared secret
```

```bash
> explain Our shared secret
dorian has access to 2 keys out of a minimum of 3 to open this secret. Here is the breakdown:
Position | Users
---------|------
1        | dorian
2        | aline, zaya
3        | dorian, zaya
```

```bash
> grant zaya 1 Our shared secret
zaya has access to 2 keys out of a minimum of 3 to open this secret. Here is the breakdown:
Position | Users
---------|------
1        | dorian, zaya
2        | aline, zaya
3        | dorian, zaya
```

```bash
dorian> open my super secret
// Open secrets in $EDITOR
```
