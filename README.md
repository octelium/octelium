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

Octelium is a free and open source, self-hosted, unified platform for zero trust resource access that is primarily meant to be a modern alternative to remote access VPNs and similar tools. It is built to be generic enough to operate as a zero-config remote access VPN, a ZTNA/BeyondCorp platform, ngrok alternative, an API gateway, an AI/LLM gateway, an infrastructure for MCP gateways and A2A architectures/meshes, a PaaS-like platform, a Kubernetes gateway/ingress and even as a homelab infrastructure.

Octelium provides a scalable zero trust architecture (ZTA) for identity-based, application-layer (L7) aware secret-less secure access via both private client-based access over WireGuard/QUIC tunnels as well as public clientless access, for both humans and workloads, to any private/internal resource behind NAT in any environment as well as to publicly protected resources such as SaaS APIs and databases, via context-aware access control on a per-request basis.

## Use Cases

Octelium is designed to be generic enough (check out the main features below for more details) to be completely or partially used as a solution for various use cases depending on your needs/requirements, notably:

- **Modern remote access VPN** A modern zero trust L-7 aware alternative to commercial remote access/corporate VPNs to provide zero-config client-based access over WireGuard/QUIC tunnels as well as client-less secret-less access via dynamic identity-based, L-7 aware, context-aware access control via policy-as-code (i.e. alternative to OpenVPN Access Server, Twingate, Tailscale, etc...).
- **Unified ZTNA/BeyondCorp architecture** A Zero Trust Network Access (ZTNA) platform/ BeyondCorp architecture (i.e. alternative to Cloudflare Access, Google BeyondCorp, Zscaler Private Access, Teleport, Fortinet, etc...).

![ZTNA](https://octelium.com/assets/ztna-CrAF5Ft7.webp)

- **Self-hosted infrastructure for secure tunnels** A self-hosted secure tunnels and reverse proxy programmable infrastructure (i.e. alternative to ngrok, Cloudflare Tunnel, etc...). You can see an example [here](https://octelium.com/docs/octelium/latest/management/guide/service/http/open-source-self-hosted-ngrok-alternative).
- **Self-hosted PaaS** A scalable PaaS-like hosting/deployment platform to deploy, scale and provide both secure as well as anonymous public hosting for your containerized applications (i.e. similar to Vercel, Netlify, etc...). You can see examples for [Next.js/Vite apps](https://octelium.com/docs/octelium/latest/management/guide/service/http/nextjs-vite), [remote VSCode](https://octelium.com/docs/octelium/latest/management/guide/service/homelab/remote-vscode-code-server), [remote Ollama](https://octelium.com/docs/octelium/latest/management/guide/service/ai/remote-ollama) and [Pi-hole](https://octelium.com/docs/octelium/latest/management/guide/service/homelab/pihole).
- **API gateway** A self-hosted, scalable, secure API gateway that takes care of access, routing, deployment and scaling of containerized microservices, authentication, L-7 aware/context aware authorization and visibility (i.e. alternative to Kong Gateway, Apigee, etc...). You can see an example [here](https://octelium.com/docs/octelium/latest/management/guide/service/http/api-gateway).
![API Gateway](https://octelium.com/assets/api-gateway-CFk9gans.webp)
- **AI gateway** A scalable AI gateway to any AI LLM providers with identity-based, context-aware access control, routing and visibility (see an example [here](https://octelium.com/docs/octelium/latest/management/guide/service/ai/ai-gateway)).
![AI Gateway](https://octelium.com/assets/ai-gateway-DJ3HDjp2.webp)
- **Unified Zero Trust Access to SaaS APIs** Unified, secret-less access, eliminating the distribution and sharing of typically long-lived/over-privileged the typically long-lived/over-privileged API keys and access tokens, access to all HTTP-based SaaS APIs for teams and workloads/applications where you can control access on a per-request basis via policy-as-code. Octelium also supports secret-less access to Kubernetes clusters, PostgreSQL/MySQL-based databases as well as to SSH servers (see the main features [here](#main-features) for more information and links).
- **MCP gateways and A2A-based architectures** A secure infrastructure for Model Context Protocol [(MCP)](https://modelcontextprotocol.io/introduction) gateways and Agent2Agent Protocol [(A2A)](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)-based architectures that provides identity management, authentication over standard OAuth2 client credentials and bearer authentication, secure remote access and deployment as well as identity-based, L7-aware access control via policy-as-code and visibility (see an example [here](https://octelium.com/docs/octelium/latest/management/guide/service/ai/self-hosted-mcp)).
![MCP Gateway](https://octelium.com/assets/mcp-gateway-CGLcJmjZ.webp)
- **Kubernetes ingress alternative** A much more advanced alternative to Kubernetes Ingress and load balancers where you can route to any remotely accessible internal resources from anywhere, not just Kubernetes services running on the same cluster, via much more than just path prefixes (e.g. identity, request headers, body content, context such as time of day, etc...) via dynamic policy-as-code.
- **Homelab** A unified self-hosted Homelab infrastructure to connect and provide secure remote access to all your resources behind NAT from anywhere (e.g. all your devices including your laptop, IoT, cloud providers, Raspberry Pis, routers, etc...) as well as a secure deployment platform to deploy and privately as well as publicly host your websites, blogs, APIs or to remotely test heavy containers (e.g. LLM runtimes such as Ollama, databases such as ClickHouse and Elasticsearch, Pi-hole, etc...).


## Main Features

- **A modern, unified, scalable zero trust architecture** Octelium is built from the ground up to control access at the application layer using a scalable architecture that is based on identity-aware proxies (IAPs) rather than at the network level using segmentation as is the case in remote access VPNs (read in detail about how Octelium works [here](https://octelium.com/docs/octelium/latest/overview/how-octelium-works)) with the following main goals:
  - A unified access platform for humans and workloads.
  - A unified architecture to access any kind of private/internal resources behind NAT (e.g. on-prem, one or more private clouds, your own laptop behind NAT, IoT, etc...) as well as protected public resources (e.g. SaaS APIs, databases, protected public SSH servers, etc...).
  - A unified architecture for both zero trust access methods:
    - Private access using VPN-like zero-config client-based zero trust network access (ZTNA) over WireGuard/QUIC tunnels with automatic private DNS.
    - Public client-less BeyondCorp access for both humans via their browsers and workloads via standard OAuth2 client credential flows and bearer authentication.
  - Built on top of Kubernetes to provide automatic horizontal scalability and availability. An Octelium _Cluster_ can run on top of a single node Kubernetes cluster running over a cheap cloud VM instance/VPS and it can also run over managed, scalable Kubernetes installations.

- **Dynamic secret-less access** Octelium's layer-7 awareness enables _Users_ to seamlessly access resources that are protected by application-layer credentials eliminating the need to expose, manage and share such typically long-lived and over-privileged secrets required to access such protected resources (read more [here](https://octelium.com/docs/octelium/latest/management/core/service/secretless)). The following protocols are currently supported:
  - HTTP-based resources (e.g. HTTP APIs, gRPC APIs, protected web apps, etc...) without having to share and expose API keys, access tokens, AWS sigv4 auth secret keys or OAuth2 client credentials (read more [here](https://octelium.com/docs/octelium/latest/management/core/service/http#secret-less-access)).
  - SSH without having to share passwords or manage keys and certificates (read more [here](https://octelium.com/docs/octelium/latest/management/core/service/ssh)).
  - Kubernetes clusters without sharing Kubeconfigs, certificates or access tokens (read more [here](https://octelium.com/docs/octelium/latest/management/core/service/kubernetes)).
  - PostgreSQL and MySQL-based databases without exposing passwords (read more [here](https://octelium.com/docs/octelium/latest/management/core/service/postgres) and [here](https://octelium.com/docs/octelium/latest/management/core/service/mysql), you can also see some examples [here](https://octelium.com/docs/octelium/latest/management/guide/service/databases/cockroachdb), [here](https://octelium.com/docs/octelium/latest/management/guide/service/databases/neon) and [here](https://octelium.com/docs/octelium/latest/management/guide/service/databases/planetscale)).
  - Any application-layer protocol that is protected by mutual TLS (mTLS) without managing PKI/sharing certificates (read more [here](https://octelium.com/docs/octelium/latest/management/core/service/secretless#mutual-tls)).



- **Context-aware, identity-based, application-layer aware access control** Octelium provides you a modern, centralized, scalable, fine-grained, dynamic, context-aware, layer-7 aware, attribute-based access control system (ABAC) on a per-request basis using modular and composable _Policies_ that enable you to write your policy-as-code using [CEL](https://cel.dev/) as well as [OPA](https://www.openpolicyagent.org/) (Open Policy Agent). You can read more in detail about _Policies_ and access control [here](https://octelium.com/docs/octelium/latest/management/core/policy).

  Octelium intentionally has no notion whatsoever of an "admin" or "superuser" _User_. In other words, zero standing privileges are the default state. Any permissions including those to the API Server can be restricted via _Policies_ and tied to time and context on a per-request basis.

- **Context-aware, identity-based, L-7 aware dynamic configuration and routing** Route to different upstreams, different credentials representing different upstream contexts and accounts using policy-as-code with CEL and OPA on a per-request basis. You can read in detail about dynamic configuration [here](https://octelium.com/docs/octelium/latest/management/core/service/dynamic-config).

- **Continuous strong authentication** A unified, continuous authentication system for both human and workload _Users_:
  - Any web identity provider (IdP) that supports OpenID Connect or SAML 2.0 (e.g. Okta, Auth0, OneLogin, AWS Cognito, etc...) as well as Github OAuth2 (read more [here](https://octelium.com/docs/octelium/latest/management/core/identity-providers#web-identity-providers)).
  - "Secret-less" authentication for workloads via OIDC-based assertions where workloads can authenticate themselves using OIDC identity tokens issued by the identity provider hosting the workload ( e.g. Azure, CI/CD providers such as GitHub Actions as well as Kubernetes clusters, etc...). You can read in detail [here](https://octelium.com/docs/octelium/latest/management/core/identity-providers#workload-identity-providers).
  - Integrate Your IdP and control access to sensitive resources based on NIST SP 800-63 Authenticator Assurance Levels (read more [here](https://octelium.com/docs/octelium/latest/management/core/identity-providers#authenticator-assurance-level)) to force using strong MFA (e.g. WebAuthn/Passkeys) via phishing resistant security keys (e.g. Yubikey).

- **OpenTelemetry-ready, application-layer aware auditing and visibility** Identity and application-layer aware visibility where every request is logged and exported in real-time to your OpenTelemetry OTLP receivers and collectors which can be further exported to log management and SIEM tools and providers. You can see some examples for [HTTP](https://octelium.com/docs/octelium/latest/management/core/service/http#visibility), [Kubernetes](https://octelium.com/docs/octelium/latest/management/core/service/kubernetes#visibility), [PostgreSQL](https://octelium.com/docs/octelium/latest/management/core/service/postgres#visibility) and [SSH](https://octelium.com/docs/octelium/latest/management/core/service/ssh).

- **Effortless, password-less, serverless SSH access** Octelium clients are capable of serving SSH even when they are not running as root enabling _Users_ to SSH into containers, IoT devices or other hosts that do not have or cannot run SSH servers. You can read more in detail about the embedded SSH mode [here](https://octelium.com/docs/octelium/latest/management/core/service/embedded-ssh).

- **Effortlessly deploy, scale and secure access to your containerized applications as _Services_** Octelium provides you out-of-the-box PaaS-like capabilities to effortlessly deploy, manage and scale your containerized applications and serve them as _Services_ to provide seamless secure client-based private access, client-less public BeyondCorp access as well as public anonymous access. You can read in detail about managed containers [here](https://octelium.com/docs/octelium/latest/management/core/service/managed-containers).

- **Centralized, declarative and programmable management** Octelium _Clusters_ are designed to be administered like Kubernetes. They can be administered via declarative management where one command (i.e. `octeliumctl apply`) is enough to (re)produce the state of the Octelium _Cluster_ anywhere (read this quick guide on the _Cluster_ management [here](https://octelium.com/docs/octelium/latest/overview/management)). The _Cluster_'s management is also centralized via its APIs which means you do not have to ever again SSH into your servers to set up configurations/rules. Instead, the `octeliumctl` CLI tool is used to control all the _Cluster_'s resources in a clean, centralized and declarative way that is dev/DevOps/GitOps friendly where you can store your _Cluster_ configurations and resources in a git repo and effortlessly reproduce them at anytime and anywhere. Furthermore, the _Cluster_ is fully programmable using gRPC-based APIs that can be compiled to your favorite programming language.

- **No change in your infrastructure is needed** Your upstream resources don't need to be aware of Octelium at all. They can be listening to any behind-NAT private network, even to localhost. No public gateways, no need to open ports behind firewalls to serve your resources wherever they are.

- **Avoiding traditional VPN networking problems altogether** Octelium's client-based private networking mode eliminates a whole class of networking and routing problems that traditional VPNs suffer from. In Octelium, each resource is represented by a _Service_ that is implemented by an identity-aware proxy (IaP) and is assigned stable private dual-stack IP address(es) within a single dual-stack private range abstracting the actual upstream resource's dynamic network details. This architecture eliminates classes of decades-old networking problems via:

  - Using a single stable route instead of injecting countless routes of the actual different remote private networks into the users' machines which cause routing conflicts.
  - Effortless dual-stack private networking where _Users_ seamlessly access _Services_ at both IPv4/IPv6 regardless of whether the upstream supports them both or not, without having to deal with the pain and inconsistency of NAT64/DNS64.
  - A unified, automatically managed, private DNS using your own domain for all resources scattered across the different remote networks that works consistently and independently of the dynamic network details of the upstreams.
  - Simultaneous support for WireGuard (Kernel, TUN as well as unprivileged implementations via [gVisor](https://gvisor.dev/)) as well as experimentally QUIC (both TUN and unprivileged via gVisor) tunnels via a lightweight zero-config client that can run in any Linux, MacOS, Windows environment as well as container environments (e.g. Kubernetes sidecar containers for your workloads).

- **Open source and designed for self-hosting** Octelium is fully open source and it is designed for single-tenant self-hosting. There is no proprietary cloud-based control plane, nor is this some crippled demo open source version of a separate fully functional SaaS paid service. You can host it on top of a single-node Kubernetes cluster running on a cheap cloud VM/VPS and you can also host it on scalable production cloud-based or on-prem multi-node Kubernetes installations with no vendor lock-in.


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

## Install your First Cluster

Read this quick guide [here](https://octelium.com/docs/octelium/latest/overview/quick-install) to install a single-node Octelium _Cluster_ on top of any cheap cloud VM/VPS instance (e.g. DigitalOcean Droplet, Hetzner server, AWS EC2, Vultr, etc...) or a local Linux machine/Linux VM inside a MacOS/Windows machine with at least 2GB of RAM and 20GB of disk storage running a recent Linux distribution (Ubuntu 24.04 LTS or later, Debian 12+, etc...), which is good enough for most development, personal or undemanding production use cases that do not require highly available multi-node _Clusters_. Once you SSH into your VPS/VM as root, you can install the _Cluster_ as follows:

```bash
curl -o install-demo-cluster.sh https://octelium.com/install-demo-cluster.sh
chmod +x install-demo-cluster.sh

# Replace <DOMAIN> with your actual domain
./install-demo-cluster.sh --domain <DOMAIN>
```

Once the _Cluster_ is installed. You can start managing it as shown in the guide [here](https://octelium.com/docs/octelium/latest/overview/management).


## Useful Links

- [What is Octelium?](https://octelium.com/docs/octelium/latest/overview/intro)
- [What is Zero Trust?](https://octelium.com/docs/octelium/latest/overview/zero-trust)
- [How Octelium works](https://octelium.com/docs/octelium/latest/overview/how-octelium-works)
- [First Steps Managing the Cluster](https://octelium.com/docs/octelium/latest/overview/management)
- [Policies and Access Control](https://octelium.com/docs/octelium/latest/management/core/policy)

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

- **Why are there so few commits for such a big project?**

  Octelium has been in active development since early 2020 with nearly 9000 manual commits but was only open sourced in May 2025 in a new repository when it became mature and stable enough.


- **Who's behind this project?**

  Octelium, so far, has been developed by George Badawi, the sole owner of Octelium Labs LLC. See how to contact me at [https://octelium.com/contact](https://octelium.com/contact). You can also email me directly at [contact@octelium.com](mailto:contact@octelium.com).


- **Is Octelium a remote access VPN?**

  Octelium can seamlessly operate as a zero-config remote access/corporate VPN. It is, however, a modern zero trust architecture that's based on identity-aware proxies (read about how Octelium works [here](https://octelium.com/docs/octelium/latest/overview/how-octelium-works)) instead of operating at layer-3 to provide dynamic fine-grained application-layer aware access control, dynamic configuration and routing, secret-less access and visibility. You can read more about the main features [here](#main-features).

- **Why is Octelium FOSS? What's the catch?**

  Octelium is a totally free and open source software. It is designed to be fully self-hosted and it has no hidden "server-side" components, nor does it pose artificial limits (e.g. SSO tax). Octelium isn't released as a yet another "fake" open source software project that only provides a very limited functionality or makes your life hard trying to self-host it in order to force you to eventually give up and switch to a separate fully functional paid SaaS version. In other words, Octelium Labs LLC is not a SaaS company. It is not a VC funded company either and it has no external funding as of today whatsoever besides from its sole owner. Therefore, you might ask: what's the catch? What's the business model? the answer is that the project is funded by a mix of dedicated support for businesses, alternative commercial licensing to AGPLv3-licensed components as well as providing additional enterprise-tier proprietary features and integrations (e.g. SIEM integrations for Splunk and similar vendors, SCIM 2.0/directory syncing from Microsoft Entra ID and Okta, managed Secret encryption at rest backed by Hashicorp Vault and similar vault providers, EDR integrations, etc...). You can read more [here](https://octelium.com/enterprise).


- **Is this project open to external contributions?**

  You are more than welcome to report bugs and request features. However, the project is not currently open to external contributions. In other words, pull requests will not be accepted. This, however, might change in the foreseeable future.

- **How to report security-related bugs and vulnerabilities?**

  Email us at [security@octelium.com](mailto:security@octelium.com).

## Legal

Octelium and Octelium logo are trademarks of Octelium Labs, LLC.

WireGuard is a registered trademark of Jason A. Donenfeld.