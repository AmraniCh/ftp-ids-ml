# TODO

## Backlog
- [ ] Added sample logs to (data/samples/)
- [ ] Anonymization script for sample logs (data/samples/)
- [ ] Standardize event_type vocabulary across parsers
- [ ] verify lines like
        'Tue May 12 04:44:48 2026 [pid 973424] FTP command: Client "::ffff:35.216.234.X"'
        are server generated or actual events sent by the client.
- [ ] consider to support feature like 'pre_auth_commands' which measures how much commands sent by the client before login.
