// Example lowering target for Capgate -> protect-mcp interop.
// policy_digest: sha256:1d249a04d50d529235784f532f6a00d7d021f8923ff71199c31b4710dbe1eb7d

permit (
  principal == Principal::"mcp-server:example-repo-agent",
  action in [Action::"fs.read", Action::"fs.write"],
  resource
) when { resource.path like "/workspace/**" };

permit (
  principal == Principal::"mcp-server:example-repo-agent",
  action == Action::"net.connect",
  resource == NetHost::"api.github.com:443"
);

permit (
  principal == Principal::"mcp-server:example-repo-agent",
  action == Action::"exec.spawn",
  resource == Binary::"chromium"
) when { context.nestedSandbox == true };
