# Open WebUI Troubleshooting Guide

## Understanding the Open WebUI Architecture

The Open WebUI system is designed to streamline interactions between the client (your browser) and the Ollama API. At the heart of this design is a backend reverse proxy, enhancing security and resolving CORS issues.

- **How it Works**: The Open WebUI is designed to interact with the Ollama API through a specific route. When a request is made from the WebUI to Ollama, it is not directly sent to the Ollama API. Initially, the request is sent to the Open WebUI backend via `/ollama` route. From there, the backend is responsible for forwarding the request to the Ollama API. This forwarding is accomplished by using the route specified in the `OLLAMA_BASE_URL` environment variable. Therefore, a request made to `/ollama` in the WebUI is effectively the same as making a request to `OLLAMA_BASE_URL` in the backend. For instance, a request to `/ollama/api/tags` in the WebUI is equivalent to `OLLAMA_BASE_URL/api/tags` in the backend.

- **Security Benefits**: This design prevents direct exposure of the Ollama API to the frontend, safeguarding against potential CORS (Cross-Origin Resource Sharing) issues and unauthorized access. Requiring authentication to access the Ollama API further enhances this security layer.

## Open WebUI: Server Connection Error

If you're experiencing connection issues, it’s often due to the WebUI docker container not being able to reach the Ollama server at 127.0.0.1:11434 (host.docker.internal:11434) inside the container . Use the `--network=host` flag in your docker command to resolve this. Note that the port changes from 3000 to 8080, resulting in the link: `http://localhost:8080`.

**Example Docker Command**:

```bash
docker run -d --network=host -v open-webui:/app/backend/data -e OLLAMA_BASE_URL=http://127.0.0.1:11434 --name open-webui --restart always ghcr.io/open-webui/open-webui:main
```

### Error on Slow Responses for Ollama

Open WebUI has a default timeout of 5 minutes for Ollama to finish generating the response. If needed, this can be adjusted via the environment variable AIOHTTP_CLIENT_TIMEOUT, which sets the timeout in seconds.

### DNS Resolution Errors ("Could not contact DNS servers", "DNS lookup failed")

Open WebUI ships the `aiodns` package, which makes `aiohttp` resolve hostnames with
c-ares on the event loop instead of calling `getaddrinfo` on a worker thread. That
keeps DNS lookups from queueing behind other blocking work, but c-ares only reads
`/etc/resolv.conf` and the hosts file — it does not use the platform name-service
stack (`nsswitch.conf`, mDNS/`.local`, NetBIOS, the Windows resolver).

Names that only the operating system knows how to resolve can therefore fail, most
commonly:

- Docker Compose service names resolved by Docker's embedded DNS server at `127.0.0.11`
  (for example an `ollama`, `vllm`, or `pipelines` container on the same network)
- hosts behind a DNS64/NAT64 translator
- `.local` and other mDNS/NetBIOS names

By default Open WebUI tries c-ares first and falls back to `getaddrinfo` for any name
c-ares cannot resolve, so these keep working. To change that, set
`AIOHTTP_CLIENT_RESOLVER`:

| Value      | Behavior                                                                 |
| ---------- | ------------------------------------------------------------------------ |
| `auto`     | Default. c-ares first, falling back to `getaddrinfo` when it fails.       |
| `aiodns`   | c-ares only. Fastest, but the names above will not resolve.               |
| `threaded` | `getaddrinfo` only. Use this if DNS is still misbehaving in your network. |

`threaded` is the resolver Open WebUI used before `aiodns` was added, so it is the
setting to reach for when an upgrade breaks name resolution that previously worked.

Note that a fallback costs one c-ares timeout the first time a name is looked up.
After that the name stays on `getaddrinfo` for as long as it keeps being used, and is
only reconsidered once it has gone `AIOHTTP_POOL_DNS_TTL` seconds (default 300)
without a request. A host you talk to regularly therefore pays that timeout once per
restart, not once per TTL. If every outbound hostname in your deployment needs the
fallback, set `AIOHTTP_CLIENT_RESOLVER=threaded` to skip c-ares entirely.

### General Connection Errors

**Ensure Ollama Version is Up-to-Date**: Always start by checking that you have the latest version of Ollama. Visit [Ollama's official site](https://ollama.com/) for the latest updates.

**Troubleshooting Steps**:

1. **Verify Ollama URL Format**:
   - When running the Web UI container, ensure the `OLLAMA_BASE_URL` is correctly set. (e.g., `http://192.168.1.1:11434` for different host setups).
   - In the Open WebUI, navigate to "Settings" > "General".
   - Confirm that the Ollama Server URL is correctly set to `[OLLAMA URL]` (e.g., `http://localhost:11434`).

By following these enhanced troubleshooting steps, connection issues should be effectively resolved. For further assistance or queries, feel free to reach out to us on our community Discord.
