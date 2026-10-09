# Firefox Policy Alignment Notes

These notes are a preparation aid, not a guarantee of Mozilla approval.

- The add-on requests only permissions used by its stated browser-protection purpose.
- All executable code is self-contained in the add-on package; remote updates are signed network-rule data only.
- Generated/bundled code is accompanied by readable source and reproducible build instructions.
- Exact third-party package versions and upstream links are supplied for review.
- Firefox 140+ built-in data declaration is used with `required: ["none"]` because iShield Extension does not collect or transmit user/personal/technical interaction data for processing outside the extension.
- The fixed signed-filter update request is disclosed in the privacy policy and reviewer notes.
