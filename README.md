# totpm: A TPM-backed command line TOTP client
`totpm` is a command line TOTP client which uses your computer's TPM to store secrets securely.
It uses fingerprint verification via fprintd to ensure that only a user that is physically present at the computer
can generate one-time codes.


## Implementation details
`totpm` can be used either in system mode or in local mode. System mode highly recommended as it is more secure
against local attackars. Local mode is only recommended in cases where the user is not able to install
system-wide software.

In both modes, an initialized `totpm` store consists of the following components:
- the `totpm` binary
- a configuration file
- a primary key stored on the system's TPM
- a system data directory, containing a secret required to unlock the primary key, and the persistent handle
  of the primary key
- one user data directory per user, containing an SQLite database of secrets

By default, the user data directory is located at `~/.local/state/totpm`.

When adding a secret, the secret is loaded into the TPM and encrypted with the primary key.
The resulting ciphertext is then stored in the SQLite secrets database together with the corresponding
service and account names. The service and account names are stored in plain text.

When generating a one-time code for an account, the secret ciphertext corresponding to the account is 
fetched from the SQLite database and loaded into the TPM. The TPM decrypts the secret and generates the one-time code.
At no point does the unencrypted secret leave the TPM.

This means that, unlike with Google Authenticator and other authenticators which allow exporting secrets or backing
them up to a cloud service, secrets stored with `totpm` are *not recoverable*.
If you lose your device or wipe the primary key secret, your secrets are gone forever and you will need to
set up MFA for your accounts again.

`totpm` can be configured to require user presence verification to add new secrets, generate one-time codes, etc.
At the time of writing, the only supported methods of presence verification are fingerprint scan via `fprintd`,
and no presence verification.

`totpm` uses the `tpm2-tss` [enhanced system API](https://tpm2-tss.readthedocs.io/en/stable/group__esys.html)
to interface with the TPM. This means that all `totpm` users need to be in the `tss` group, to allow TPM access.


### System mode
In this mode, a dedicated `totpm` user is created. The system data directory and all files therein
are owned by this user. The primary key secret is stored with permissions 0600, i.e. only the `totpm` user
is able to read it.

By default, the system data directory is located at `/var/lib/totpm` and the configuration file at
`/etc/totpm.conf`.

The `totpm` binary is owned by the `totpm` user and has the SUID bit set. When an operation requiring the
TPM is requested, if presence verification succeeds, it reads the primary key secret, feeds it to the TPM,
wipes it from memory, and then assumes the privileges of the calling user before proceeding to perform
the requested TPM operation.
In this way, a local attacker without root privileges is prevented from generating new one-time passwords
at will.


### Local mode
In this mode, `totpm` always runs as the calling user. This means that the secret protecting the primary
key is accessible to the user as well. Presence verification is disabled by default, as a local attacker
could just grab the secret and talk to the TPM directly.

By default, the system data directory is located at `~/.local/state/totpm/system` and the config file at
`~/.config/totpm.conf`.


## Security
Depending on your threat model, totpm can be either more or less secure than using a TOTP authenticator
on your phone, such as Google Authenticator.


### Google Authenticator
With Google Authenticator, secrets are stored in device memory *and* on Google's servers.
An attacker with access to your Google account or root access to your device can recover your secrets
and use them to generate one-time codes at their leisure.
Thanks to Android's security model however, an attacker with non-root access to your phone is not able to recover
your secrets or generate one-time codes.

Being located on a separate physical device, phone-based authenticators would be considered a second factor
("something you have") when you are logging into an account on your computer (i.e. *not* on the authenticator device),
*if they did not support exporting/backing up secrets*.
However, a local attacker on your computer can still sniff one-time codes while they are being entered,
making the distinction less useful in practice.


### totpm
With `totpm`, secrets are stored in your computer's TPM, and can't be recovered even by an attacker with root access.
A local root attacker can, however, generate one-time codes for as long as they can maintain root access.
In system mode with presence verification enabled, a non-root local attacker is not able to generate one-time codes
due to the secret protecting the primary key being owned by a dedicated user and `totpm` refusing to generate codes
without valid presence verification.

In local mode however, a local non-root attacker can generate one-time codes at will for as long as they can maintain
access to your account.

Using the TPM to store TOTP secrets, `totpm` is closer to truly being a "something you have" second factor: the secrets
can not be used on any other physical machine and can not be exported.
This holds whether you are logging into your accounts from the computer running `totpm` or from another device.
Sniffing one-time codes may be slightly easier for a local attacker when logging into an account using
the computer running `totpm`, than if using a phone-based authenticator, however.
