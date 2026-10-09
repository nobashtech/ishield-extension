# Publish iShield Extension to GitHub

1. Review the source and [SECURITY.md](../SECURITY.md). Never commit signing keys, personal tokens, `.env` files, credentials or user data.
2. Extract this source ZIP so that `README.md`, `package.json`, `.github/` and `extensions/` are at the repository root. Upload the **extracted files**, not the ZIP itself.
3. **GitHub Desktop (easiest):** choose **File → Add Local Repository**. If prompted, choose **Create a Repository here** with name `ishield-extension`; then commit and choose **Publish Repository**. Select the appropriate GitHub owner and Public visibility only after reviewing the files. You do not need to pre-create a GitHub web repository for this method.
4. **Terminal alternative:** first create an empty GitHub repository named `ishield-extension` (without an auto-generated README/license/gitignore). Then run these commands inside the extracted project root:

```bash
git init
git branch -M main
git add .
git commit -m "Initial iShield Extension source release"
git remote add origin https://github.com/YOUR_ORG/ishield-extension.git
git push -u origin main
```

Replace `YOUR_ORG` with the GitHub owner or organization you control.

## Check before committing

```bash
npm ci
npm run ci
npm test
```

The repository includes source for four store-specific targets and compatibility notes for Brave. Only distribute a store ZIP after completing the corresponding store review checklist.

## GitHub release

Tag a tested release (for example `v1.0.0.2`) only after selecting a version higher than the already-published store version. Attach actual browser-specific build archives to a GitHub Release; keep build outputs and signing material out of git history.
