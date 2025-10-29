[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![License](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Discord](https://img.shields.io/badge/chat-on%20discord-7289da.svg)](https://octelium.com/external/discord)
[![Slack](https://img.shields.io/badge/Slack-purple?logo=slack&logoColor=white)](https://octelium.com/external/slack)

<div align="center">
    <br />
    <img src="./unsorted/logo/main.png" alt="Octelium Logo" width="350"/>
    <h1>Octelium</h1>
</div>

## Table of Contents

- [What is Octelium?](#what-is-octelium)
- [Use Cases](#use-cases)
- [Main Features](#main-features)
- [Try Octelium in a Codespace](#try-octelium-in-a-codespace)
- [Install CLI Tools](#install-cli-tools)
- [Install your First Cluster](#install-your-first-cluster)
- [Useful Links](#useful-links)
- [License](#license)
- [Support](#support)
- [Frequently Asked Questions](#frequently-asked-questions)
- [Legal](#legal)


## What is Octelium?

Octelium is a free and open source, self-hosted, unified zero trust secure access platform that is flexible enough to operate as a modern zero-config remote access VPN, a comprehensive Zero Trust Network Access (ZTNA)/BeyondCorp platform, an ngrok/Cloudflare Tunnel alternative, an API gateway, an AI/LLM gateway, a scalable infrastructure for access and deployment to build MCP gateways and A2A architectures/meshes, a PaaS-like platform, a Kubernetes gateway/ingress and even as a homelab infrastructure.

Octelium provides a scalable zero trust architecture (ZTA) for identity-based, application-layer (L7) aware secretless secure access via both private client-based access over WireGuard/QUIC tunnels as well as public clientless access, for both humans and workloads, to any private/internal resource behind NAT in any environment as well as to publicly protected resources such as SaaS APIs and databases, via context-aware access control on a per-request basis.


![Octelium](https://octelium.com/assets/ztna-CrAF5Ft7.webp)

## Use Cases


Octelium is a versatile platform that can serve as a complete or partial solution for many different needs. Here are some of the key use cases:

* **Modern Remote Access VPN:** A zero-trust, layer-7 aware alternative to commercial remote access/corporate VPNs like **OpenVPN Access Server, Twingate, and Tailscale**, providing both zero-config client access over WireGuard/QUIC and client-less access via dynamic, identity-based, context-aware _Policies_.
* **Unified ZTNA/BeyondCorp Architecture:** A comprehensive Zero Trust Network Access (ZTNA) platform, similar to **Cloudflare Access, Google BeyondCorp, or Teleport**.
* **Self-Hosted Secure Tunnels:** A programmable infrastructure for secure tunnels and reverse proxies for both secure identity-based as well as anonymous clientless access, offering a powerful, self-hosted alternative to **ngrok or Cloudflare Tunnel**. You can see an example [here](https://octelium.com/docs/octelium/latest/management/guide/service/http/open-source-self-hosted-ngrok-alternative).
* **Self-Hosted PaaS:** A scalable platform to deploy, manage, and host your containerized applications, similar to **Vercel or Netlify**. See an example for [Next.js/Vite apps](https://octelium.com/docs/octelium/latest/management/guide/service/http/nextjs-vite).
* **API Gateway:** A self-hosted, scalable, and secure API gateway for microservices, providing a robust alternative to **Kong Gateway or Apigee**. You can see an example [here](https://octelium.com/docs/octelium/latest/management/guide/service/http/api-gateway).
* **AI Gateway:** A scalable AI gateway with identity-based access control, routing, and visibility for any AI LLM provider. See an example [here](https://octelium.com/docs/octelium/latest/management/guide/service/ai/ai-gateway).
* **Unified Zero Trust Access to SaaS APIs:** Provides secretless access to SaaS APIs for both teams and workloads, eliminating the need to manage and distribute long-lived and over-privileged API keys. See a generic example [here](https://octelium.com/docs/octelium/latest/management/guide/service/http/zero-trust-saas-api), AWS Lambda [here](https://octelium.com/docs/octelium/latest/management/guide/service/http/lambda-zero-trust-secretless-access), and AWS S3 [here](https://octelium.com/docs/octelium/latest/management/guide/service/http/s3-zero-trust-secretless-access).
- **MCP Gateways and A2A-based Architectures** A secure infrastructure for Model Context Protocol [(MCP)](https://modelcontextprotocol.io/introduction) gateways and Agent2Agent Protocol [(A2A)](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)-based architectures that provides identity management, authentication over standard OAuth2 client credentials and bearer authentication, secure remote access and deployment as well as identity-based, L7-aware access control via policy-as-code and visibility (see an example [here](https://octelium.com/docs/octelium/latest/management/guide/service/ai/self-hosted-mcp)).
* **Homelab:** A unified self-hosted Homelab infrastructure to connect and provide secure remote access to all your resources behind NAT from anywhere (e.g. all your devices including your laptop, IoT, cloud providers, Raspberry Pis, routers, etc...) as well as a secure deployment platform to deploy and privately as well as publicly host your websites, blogs, APIs or to remotely test heavy containers (e.g. LLM runtimes such as Ollama, databases such as ClickHouse and Elasticsearch, Pi-hole, etc...). See examples for [remote VSCode](https://octelium.com/docs/octelium/latest/management/guide/service/homelab/remote-vscode-code-server), and [Pi-hole](https://octelium.com/docs/octelium/latest/management/guide/service/homelab/pihole).
* **Kubernetes Ingress Alternative:** A more advanced alternative to standard Kubernetes ingress controllers and load balancers, allowing you to route to any Kubernetes service via dynamic, L7-aware policy-as-code.


## Main Features

- **A Modern, Unified Zero Trust Architecture** Built on a scalable architecture of identity-aware proxies to control access at the application layer (L7), Octelium unifies access for humans and workloads to both private and protected public resources. It supports both zero-config VPN-like client-based access over WireGuard/QUIC and client-less BeyondCorp access, all built on top of Kubernetes for automatic scalability (read in detail about how Octelium works [here](https://octelium.com/docs/octelium/latest/overview/how-octelium-works)).


- **Dynamic Secretless Access** Octelium's layer-7 awareness enables _Users_ to seamlessly access resources protected by application-layer credentials without exposing, managing and distributing such secrets (read more [here](https://octelium.com/docs/octelium/latest/management/core/service/secretless)). This works for HTTP APIs without sharing API keys and access tokens, SSH servers with sharing passwords and private keys, Kubernetes clusters, PostgreSQL/MySQL databases as well as any L7 protocol protected by mTLS.


- **Modern, Dynamic, Fine-grained Access Control** Octelium provides you a modern, centralized, scalable, fine-grained, dynamic, context-aware, layer-7 aware, attribute-based access control system (ABAC) on a per-request basis (read more [here](https://octelium.com/docs/octelium/latest/management/core/policy)) with policy-as-code using [CEL](https://cel.dev/) and [OPA](https://www.openpolicyagent.org/) (Open Policy Agent). Octelium has no notion of an "admin" user, enforcing zero standing privileges by default.

- **Context-aware, identity-based, L7-aware dynamic configuration and routing** Route to different upstreams, different credentials representing different upstream contexts and accounts using policy-as-code with CEL and OPA on a per-request basis. You can read in detail about dynamic configuration [here](https://octelium.com/docs/octelium/latest/management/core/service/dynamic-config).


- **Continuous Strong Authentication** A unified authentication system for both human and workload _Users_, supporting any web identity provider (IdP) that uses OpenID Connect or SAML 2.0 as well as GitHub OAuth2 (read more [here](https://octelium.com/docs/octelium/latest/management/core/identity-providers#web-identity-providers)). It also allows for secretless authentication for workloads via OIDC-based assertions (read more [here](https://octelium.com/docs/octelium/latest/management/core/identity-providers#workload-identity-providers)). Built-in support for MFA/re-authentication/login via FIDO2/WebAuthn/Passkey, TOTP and TPM 2.0 _Authenticators_.


- **OpenTelemetry-native Auditing and Visibility** Real-time, identity-based, L7-aware visibility and access logging. Every request is logged and exported to your OpenTelemetry OTLP receivers for seamless integration with your log management and SIEM tools.


- **Effortless, Passwordless SSH** Octelium clients can serve SSH even without root access, enabling you to SSH into containers, IoT devices, or other hosts that can't run an SSH server (read more [here](https://octelium.com/docs/octelium/latest/management/core/service/embedded-ssh)).


- **Effortlessly deploy, scale and secure access to your containerized applications as _Services_** Octelium provides you out-of-the-box PaaS-like capabilities to effortlessly deploy, manage and scale your containerized applications and serve them as _Services_ to provide seamless secure client-based private access, client-less public BeyondCorp access as well as public anonymous access. You can read in detail about managed containers [here](https://octelium.com/docs/octelium/latest/management/core/service/managed-containers).


- **Centralized and Declarative Management** Manage your Octelium Clusters like Kubernetes with declarative management using the `octeliumctl` CLI (read this quick management guide [here](https://octelium.com/docs/octelium/latest/overview/management)). You can store your _Cluster_ configurations in Git for easy reproduction and GitOps workflows.

- **No change in your infrastructure is needed** Your upstream resources don't need to be aware of Octelium at all. They can be listening to any behind-NAT private network, even to localhost. No public gateways, no need to open ports behind firewalls to serve your resources wherever they are.

- **Avoids Traditional VPN Networking Problems** Octelium’s client-based networking eliminates a whole class of networking and routing issues that traditional VPNs suffer from. Support for dual-stack private networking regardless of the support at the upstreams and without having to deal with the pain and inconsistency of NAT64/DNS64. Unified private DNS using your own domain. Simultaneous support for WireGuard (Kernel, TUN as well as unprivileged implementations via [gVisor](https://gvisor.dev/)) as well as experimentally QUIC (both TUN and unprivileged via gVisor) tunnels via a lightweight zero-config client that can run in any Linux, MacOS, Windows environment as well as container environments (e.g. Kubernetes sidecar containers for your workloads).

- **Open source and designed for self-hosting** Octelium is fully open source and it is designed for single-tenant self-hosting. There is no proprietary cloud-based control plane, nor is this some crippled demo open source version of a separate fully functional SaaS paid service. You can host it on top of a single-node Kubernetes cluster running on a cheap cloud VM/VPS and you can also host it on scalable production cloud-based or on-prem multi-node Kubernetes installations with no vendor lock-in.


## Install your First Cluster

Read this quick guide [here](https://octelium.com/docs/octelium/latest/overview/quick-install) to install a single-node Octelium _Cluster_ on top of any cheap cloud VM/VPS instance (e.g. DigitalOcean Droplet, Hetzner server, AWS EC2, Vultr, etc...) or a local Linux machine/Linux VM inside a MacOS/Windows machine with at least 2GB of RAM and 20GB of disk storage running a recent Linux distribution (Ubuntu 24.04 LTS or later, Debian 12+, etc...), which is good enough for most development, personal or undemanding production use cases that do not require highly available multi-node _Clusters_. Once you SSH into your VPS/VM as root, you can install the _Cluster_ as follows:

```bash
curl -o install-demo-cluster.sh https://octelium.com/install-demo-cluster.sh
chmod +x install-demo-cluster.sh

# Replace <DOMAIN> with your actual domain
./install-demo-cluster.sh --domain <DOMAIN>
```

Once the _Cluster_ is installed. You can start managing it as shown in the guide [here](https://octelium.com/docs/octelium/latest/overview/management).

## Try Octelium in a Codespace

You can install and manage a demo Octelium _Cluster_ inside a GitHub Codespace without having to install it on a real VM/machine/Kubernetes cluster and simply use it as a playground to get familiar with how the _Cluster_ is managed. Visit the playground GitHub repository [here](https://github.com/octelium/playground) and run it in a Codespace then follow the README instructions there to install the _Cluster_ and start interacting with it.

## Install CLI Tools

You can see all available options [here](https://octelium.com/docs/octelium/latest/install/cli/install). You can quickly install the CLIs of the pre-built binaries as follows:

For Linux and MacOS

```bash
curl -fsSL https://octelium.com/install.sh | bash
```

For Windows in Powershell

```powershell
iwr https://octelium.com/install.ps1 -useb | iex
```

## Useful Links

- [What is Octelium?](https://octelium.com/docs/octelium/latest/overview/intro)
- [What is Zero Trust?](https://octelium.com/docs/octelium/latest/overview/zero-trust)
- [How Octelium works](https://octelium.com/docs/octelium/latest/overview/how-octelium-works)
- [First Steps to Managing the Cluster](https://octelium.com/docs/octelium/latest/overview/management)
- [Policies and Access Control](https://octelium.com/docs/octelium/latest/management/core/policy)
- [Secretless Access](https://octelium.com/docs/octelium/latest/management/core/service/secretless)
- [Connecting to Clusters](https://octelium.com/docs/octelium/latest/user/cli/connect)

## License

Octelium is free and open source software:

* The Client-side components are licensed with the Apache 2.0 License. This includes:
  - The code of the `octelium`, `octeliumctl` and `octops` CLIs as seen in the `/client` directory.
  - The `octelium-go` Golang SDK and the Golang protobuf APIs in the `/apis` directory.
  - The `/pkg` directory.
* The Cluster-side components (all the components in the `/cluster` directory) are licensed with the GNU Affero General Public (AGPLv3) License. Octelium Labs also provides a commercial license as an alternative for businesses that do not want to comply with the AGPLv3 license (read more [here](https://octelium.com/enterprise)).

## Support

- [Octelium Docs](https://octelium.com/docs/octelium/latest/overview/intro)
- [Discord Community](https://octelium.com/external/discord)
- [Slack Community](https://octelium.com/external/slack)
- [Contact via Email](mailto:contact@octelium.com)
- [Reddit Community](https://www.reddit.com/r/octelium/)

## Frequently Asked Questions


- **What is the current status of the project?**

  It's now in public beta. It's basically v1.0 but with bugs. The architecture, main features and APIs had been stabilized before the project was open sourced and made publicly available.

- **Who's behind this project?**

  Octelium, so far, has been developed by George Badawi, the sole owner of Octelium Labs LLC. See how to contact me at [https://octelium.com/contact](https://octelium.com/contact). You can also email me directly at [contact@octelium.com](mailto:contact@octelium.com).


- **Is Octelium a remote access VPN?**

  Octelium can seamlessly operate as a zero-config remote WireGuard/QUIC-based access/corporate VPN from a layer-3 perspective. It is, however, a modern zero trust architecture that's based on identity-aware proxies (read about how Octelium works [here](https://octelium.com/docs/octelium/latest/overview/how-octelium-works)) instead of operating at layer-3 to provide dynamic fine-grained application-layer (L7) aware access control, dynamic configuration and routing, secretless access and visibility. You can read more about the main features [here](#main-features).

- **Why is Octelium FOSS? What's the catch?**

  Octelium is a totally free and open source software. It is designed to be fully self-hosted and it has no hidden "server-side" components, nor does it pose artificial limits (e.g. SSO tax). Octelium isn't released as a yet another "fake" open source software project that only provides a very limited functionality or makes your life hard trying to self-host it in order to force you to eventually give up and switch to a separate fully functional paid SaaS version. In other words, Octelium Labs LLC is not a SaaS company. It is not a VC funded company either and it has no external funding as of today whatsoever besides from its sole owner. Therefore, you might ask: what's the catch? What's the business model? the answer is that the project is funded by a mix of dedicated support for businesses, alternative commercial licensing to AGPLv3-licensed components as well as providing additional enterprise-tier proprietary features and integrations (e.g. SIEM integrations for Splunk and similar vendors, SCIM 2.0/directory syncing from Microsoft Entra ID and Okta, managed Secret encryption at rest backed by Hashicorp Vault and similar vault providers, EDR integrations, etc...). You can read more [here](https://octelium.com/enterprise).


- **Is this project open to external contributions?**

  You are more than welcome to report bugs and request features. However, the project is not currently open to external contributions. In other words, pull requests will not be accepted. This, however, might change in the foreseeable future.

- **How to report security-related bugs and vulnerabilities?**

  Email us at [security@octelium.com](mailto:security@octelium.com).

## Legal

Octelium and Octelium logo are trademarks of Octelium Labs, LLC.

WireGuard is a registered trademark of Jason A. Donenfeld.