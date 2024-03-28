## Etherspot Module Isolation Hook

### Goal
I believe that an ERC7579 Executor should not be involved in the installation and removal of other Modules. Just as apps in Android cannot install or uninstall each other, maintaining isolation between modules ensures greater security. This is the reason I decided to create this particular hook.