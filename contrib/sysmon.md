# Sysmon with Sentiel

Several built-in rules (for example encoded PowerShell and Run key persistence) read Sysmon events. Without Sysmon, Sentiel still works: the channel is reported as "not installed" by `sentiel doctor` and the other sources continue. This guide is Windows only.

Sentiel does not download or install anything for you.

## 1. Install Sysmon

1. Get Sysmon from Microsoft Sysinternals (https://learn.microsoft.com/sysinternals/downloads/sysmon) and check its signature.
2. Pick a configuration file. Without one, Sysmon logs very little. Two widely used community configurations are SwiftOnSecurity/sysmon-config and olafhartong/sysmon-modular. They are suggestions: read the file before using it and adjust it to your machine.
3. In an elevated (administrator) terminal, install it with the configuration:

   ```
   sysmon64.exe -accepteula -i sysmonconfig.xml
   ```

   To change the configuration later: `sysmon64.exe -c sysmonconfig.xml`.

## 2. The channel Sentiel reads

Sysmon writes to the Windows event channel `Microsoft-Windows-Sysmon/Operational`. Sentiel reads it together with `Security` and `System` when `[sources] windows = true` (the default on Windows). If the channel does not exist, Sentiel skips it.

## 3. Run as administrator

Reading the Security log needs an administrator shell. Open PowerShell as administrator before running `sentiel scan` or `sentiel watch`, or run Sentiel as a service with `contrib/sentiel-task.xml` (Task Scheduler, runs as SYSTEM). Without administrator rights Sentiel says so and continues with the other sources.

## 4. Check it

```
sentiel doctor
```

In the table, look for the row `source:windows:Microsoft-Windows-Sysmon/Operational`:

- `readable`: working.
- `channel not installed`: the Sysmon channel does not exist, so Sysmon is not installed (or its service is not running).
- `run as administrator`: open an elevated terminal.

Then run `sentiel scan` and `sentiel alerts`.
