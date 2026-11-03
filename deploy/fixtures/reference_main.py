"""Run the MCP Everything Server (conformance reference) on 0.0.0.0 inside a container pod network."""
import os

from mcp_everything_server import server

if __name__ == '__main__':
    server.mcp.run(transport='streamable-http', host='0.0.0.0', port=int(os.environ.get('MCP_PORT', '3221')),
                   event_store=server.event_store, retry_interval=100)
