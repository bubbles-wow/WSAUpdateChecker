# Usage:
All scripts are run using Github Actions.
You should set up several repos secrets as follow:
|       Name         |                             Value                              |
| ------------------ | -------------------------------------------------------------- |
| ARCHIVE_REPOSITORY | The archive repos name in your account to storage the package. |
| OWNER_EMAIL        | Your current Github account's email.                           |
| PAT                | Github personal access token with `workflow` permission.       |
| HOST_SERVER        | SMTP server for sender's email.                                |
| SENDER_EMAIL       | The sender email used to send notification.                    |
| SENDER_PASSWORD    | The sender's email password.                                   |

Notice: The PAT and OWNER_EMAIL keys must be set to the correct values.

# Credits:
**[MagiskOnWSALocal](https://github.com/LSPosed/MagiskOnWSALocal)**