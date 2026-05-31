# Publishing Ghost Security Extension to VS Code Marketplace

## One-time setup (15 minutes)

### 1. Create a publisher account
1. Go to https://marketplace.visualstudio.com/manage
2. Sign in with Microsoft account
3. Create publisher: `ghost-security`
4. Add publisher to `package.json` → `"publisher": "ghost-security"` ✅ already set

### 2. Get Personal Access Token
1. Go to https://dev.azure.com → Your organization
2. User Settings → Personal Access Tokens
3. New Token:
   - Name: "ghost-security-marketplace"
   - Organization: All accessible organizations
   - Scopes: **Marketplace → Manage**
4. Copy the token (shown once!)

### 3. Login with vsce
```bash
cd vscode-extension
npm install -g @vscode/vsce
vsce login ghost-security
# Enter your PAT when prompted
```

## Publish (1 command)
```bash
# From vscode-extension/ directory:
vsce publish
# OR bump version and publish:
vsce publish minor    # 1.0.0 → 1.1.0
vsce publish patch    # 1.0.0 → 1.0.1
```

## Verify
Extension live at:
https://marketplace.visualstudio.com/items?itemName=ghost-security.ghost-security

Users install with:
```
ext install ghost-security.ghost-security
```

## Auto-publish via GitHub Actions
```yaml
# .github/workflows/publish-extension.yml
name: Publish VS Code Extension
on:
  push:
    tags: ['v*']
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-node@v4
      with: {node-version: '20'}
    - run: cd vscode-extension && npm install && npx vsce publish
      env:
        VSCE_PAT: ${{ secrets.VSCE_PAT }}
```

## Current build status
- ✅ TypeScript compiled → out/extension.js
- ✅ Icon: images/icon.png (128x128)
- ✅ FunC syntax grammar included
- ✅ .vsix package built: ghost-security-1.0.0.vsix
- ⏳ Publisher account (your action required)
- ⏳ PAT token (your action required)

## Expected results after publish
- 100–500 installs in first week (TON/Web3 community is small but tight)
- DAU converts to SaaS signups at ~5% rate
- 100 DAU → 5 paid users → $2,500 MRR
