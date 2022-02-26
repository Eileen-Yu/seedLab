# Lab Exercise2

### Lijun Yu



## 1. Setup two VMs in Azure under the same Network

To meet the prerequisites of this lab, I used Azure to setup instances. 

First, I created a resource group:

```shell
az group create --name CreateVNetQS-rg --location eastus
```

Next, I created a virtual network `myVNet` under the resource group:

```shell
az network vnet create --name myVNet --resource-group CreateVNetQS-rg --subnet-name default
```

Then two instances is successfully created:

```shell
az vm create --resource-group CreateVNetQS-rg --name myVM1 --image UbuntuLTS --generate-ssh-keys --public-ip-address myPublicIP-myVM1 --no-wait

az vm create --resource-group CreateVNetQS-rg --name myVM2 --image UbuntuLTS --generate-ssh-keys --public-ip-address myPublicIP-myVM2 --no-wait
```

The result is as followed:

```json
❯ az vm list-ip-addresses
[
  {
    "virtualMachine": {
      "name": "myVM1",
      "network": {
        "privateIpAddresses": [
          "10.0.0.4"
        ],
        "publicIpAddresses": [
          {
            "id": "/subscriptions/2abf4044-b29f-4de6-861d-1aede8b9f933/resourceGroups/CreateVNetQS-rg/providers/Microsoft.Network/publicIPAddresses/myPublicIP-myVM1",
            "ipAddress": "20.127.40.32",
            "ipAllocationMethod": "Dynamic",
            "name": "myPublicIP-myVM1",
            "resourceGroup": "CreateVNetQS-rg"
          }
        ]
      },
      "resourceGroup": "CreateVNetQS-rg"
    }
  },
  {
    "virtualMachine": {
      "name": "myVM2",
      "network": {
        "privateIpAddresses": [
          "10.0.0.5"
        ],
        "publicIpAddresses": [
          {
            "id": "/subscriptions/2abf4044-b29f-4de6-861d-1aede8b9f933/resourceGroups/CreateVNetQS-rg/providers/Microsoft.Network/publicIPAddresses/myPublicIP-myVM2",
            "ipAddress": "20.127.47.71",
            "ipAllocationMethod": "Dynamic",
            "name": "myPublicIP-myVM2",
            "resourceGroup": "CreateVNetQS-rg"
          }
        ]
      },
      "resourceGroup": "CreateVNetQS-rg"
    }
  }
]
```

As shown above, the instances own the private IP addresses`10.0.0.4` and `10.0.0.5`. 

Now let's login to the instances by ssh:

<img src="https://drive.google.com/uc?id=1lmDwy4L2hDha1ds-ymixiuuV-FurV7mf" alt="ssh-login screenshot" style="zoom: 50%;" />

## 2. Enable Access between instances through Telnet

First, install Telnet:

```shell
sudo apt-get update && \
     apt install telnetd -y
```

Check the status of the Telnet server:

```shell
systemctl status inetd
```

![截屏2022-02-05 上午12.51.30](/Users/eileen/Library/Application Support/typora-user-images/截屏2022-02-05 上午12.51.30.png)

Then verify the accessibility between the two instances through Telnet.![截屏2022-02-05 上午12.53.30](/Users/eileen/Library/Application Support/typora-user-images/截屏2022-02-05 上午12.53.30.png)

## 3. Setup Iptables to block Telnet and Facebook

Add the rule to block outbound request to access telnet server:

```shell
sudo iptables -A OUTPUT -p tcp --dport telnet -j REJECT
```

The result is shown below as the telnet request is blocked.

![截屏2022-02-05 上午12.58.28](/Users/eileen/Library/Application Support/typora-user-images/截屏2022-02-05 上午12.58.28.png)

Similarly add another rule to block Facebook.

First check if the website is accessible.

![截屏2022-02-05 上午1.01.22](/Users/eileen/Library/Application Support/typora-user-images/截屏2022-02-05 上午1.01.22.png)

Then check its IP address:

![截屏2022-02-05 上午1.06.32](/Users/eileen/Library/Application Support/typora-user-images/截屏2022-02-05 上午1.06.32.png)

Add rules by:

```shell
sudo iptables -A OUTPUT -d 31.13.66.35 -j DROP
```

Now it should not be available.

![截屏2022-02-05 上午1.07.25](/Users/eileen/Library/Application Support/typora-user-images/截屏2022-02-05 上午1.07.25.png)

## 4. Bypass the Telnet restriction through ssh

To do this, we need another instance, so setup VM3 like VM1 and VM2. Add a user for telnet whose name is `tlenetuser`.

Verifiying the connection, VM1 cannot access VM3 through Telnet, but VM2 can.![截屏2022-02-05 上午1.49.31](/Users/eileen/Library/Application Support/typora-user-images/截屏2022-02-05 上午1.49.31.png)

![截屏2022-02-05 上午1.49.52](/Users/eileen/Library/Application Support/typora-user-images/截屏2022-02-05 上午1.49.52.png)

To bypass the Telnet restriction, I setup an ssh tunnel between VM1 and VM2.

```shell
ssh -L 8000:10.0.0.6:23 10.0.0.5
```

To test if port 8000 is bind:

![截屏2022-02-05 上午1.55.56](/Users/eileen/Library/Application Support/typora-user-images/截屏2022-02-05 上午1.55.56.png)

Try telnet localhost:8000:

![截屏2022-02-05 上午1.56.42](/Users/eileen/Library/Application Support/typora-user-images/截屏2022-02-05 上午1.56.42.png)



Then try to bypass Facefook by:

```shell
 ssh -D 8000 -C 10.0.0.5
```

Since I am using non-GUI Linux, so I used the CLI tool `httpie` to access Facebook, which is also available to introduce socks proxy.

```shell
http --proxy=http:socks5://localhost:8000 --proxy=https:socks5://localhost:8000 https://www.facebook.com
```

![截屏2022-02-05 下午9.03.08](/Users/eileen/Library/Application Support/typora-user-images/截屏2022-02-05 下午9.03.08.png)

## 5. Bypass an internal web server by a reverse ssh tunnel

Background: I have a simple http server running on VM1 port 8080. Any inbound request at port 22 and 8080 is rejected. I also have a VM2 with a ssh account to get access to VM1(which is not available now due to the firewall). My host is able to access VM2 through ssh. The goal is to use my host to access the internal web service of VM1.

First, setup a reverse ssh tunnel between VM1 and VM2.

```shell
ssh -f -N -T -R22222:localhost:22 10.0.0.5
```

VM1 sent the request to VM2 for ssh connection on VM2's port 22222. Then VM2 can access VM1 through its own port 22222. That way bypass the firewall.

Then bind VM2's port 9000 with 'localhost:8080' at port 22222 so as to access VM1's internal web service. 

```shell
ssh -N -L 9000:127.0.0.1:8080 -p 22222 localhost
```

Finally bind my host's port 9001 with the ssh tunnel to VM2.

```shell
ssh -D 9001 20.127.47.71
```

So now I can get access to port 8080 of VM1 through the following command:

```shell
http --proxy=http:socks5://localhost:9001 http://127.0.0.1:9000/key
```

![截屏2022-02-05 下午10.26.53](/Users/eileen/Library/Application Support/typora-user-images/截屏2022-02-05 下午10.26.53.png)

## 6. Netfilter through LKM

Below is the implementation of a simple Linux Lodable Kernal Module to block inbound requests to port 8080.

```C
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

static struct nf_hook_ops *nfho = NULL;

static unsigned char *ip_address = "\x7F\x00\x00\x01"; // Localhost: 127.0.0.1

static unsigned int hfunc(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  if (!skb)
    return NF_ACCEPT;

  struct iphdr *iph;
  struct tcphdr *tcph;

  iph = ip_hdr(skb);

  // Accept request from localhost
  if(iph->saddr == *(unsigned int*)ip_address){
    return NF_ACCEPT;
  }

  // Block request over 8080
  if (iph->protocol == IPPROTO_TCP) {
    tcph = tcp_hdr(skb);
    if (ntohs(tcph->dest) == 8080) {
      return NF_DROP;
    }
  }

  return NF_ACCEPT;
}

static int __init LKM_init(void)
{
  nfho = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);

  /* Initialize netfilter hook */
  nfho->hook 	= (nf_hookfn*)hfunc;		/* hook function */
  nfho->hooknum 	= NF_INET_PRE_ROUTING;		/* received packets */
  nfho->pf 	= PF_INET;			/* IPv4 */
  nfho->priority 	= NF_IP_PRI_FIRST;		/* max hook priority */

  int ret = nf_register_net_hook(&init_net, nfho);
  return ret;
}

static void __exit LKM_exit(void)
{
  nf_unregister_net_hook(&init_net, nfho);
  kfree(nfho);
}

module_init(LKM_init);
module_exit(LKM_exit);

```

Now in VM2, I cannot access VM1(10.0.0.4)'s port 8080. But still since I'm using the ssh to bypass the firewall, I can access it art my host.

To test the result, I installed a Tshark, which is the headless Wireshark.

If send normal request, the result would be like:

![截屏2022-02-06 下午10.24.34](/Users/eileen/Library/Application Support/typora-user-images/截屏2022-02-06 下午10.24.34.png)

But if try to bypass, the result is:

![截屏2022-02-06 下午10.25.21](/Users/eileen/Library/Application Support/typora-user-images/截屏2022-02-06 下午10.25.21.png)