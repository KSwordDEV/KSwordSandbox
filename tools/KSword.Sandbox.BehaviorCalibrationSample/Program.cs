using System.Text;
using System.Text.Json;
using Microsoft.Win32;

namespace KSword.Sandbox.BehaviorCalibrationSample;

internal static class Program
{
    private const string Incoming = @"C:\KSwordSandbox\incoming\";
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const int Count = 24;
    private const int BytesEach = 2048;
    private const long MaxCopyBytes = 128L * 1024 * 1024;

    private static bool InApprovedGuest()
    {
        if (!OperatingSystem.IsWindows() || Environment.ProcessPath is null) return false;
        if (!Path.GetFullPath(Environment.ProcessPath).StartsWith(Incoming, StringComparison.OrdinalIgnoreCase)) return false;
        using RegistryKey? bios = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\BIOS");
        string vendor = bios?.GetValue("SystemManufacturer") as string ?? "";
        string model = bios?.GetValue("SystemProductName") as string ?? "";
        return vendor.Contains("VMware", StringComparison.OrdinalIgnoreCase)
            || model.Contains("VMware", StringComparison.OrdinalIgnoreCase);
    }

    private static string WorkDirectory(string[] args, string runId)
    {
        string tempBase = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "KSwordBehaviorCalibration"));
        string guestBase = @"C:\KSwordSandbox\behavior-calibration";
        if (args.Length != 0 && (args.Length != 2 || args[0] != "--root"))
            throw new ArgumentException("Only --root <approved base directory> is supported.");
        string selected = args.Length == 0 ? tempBase : args[1];
        if (!Path.IsPathFullyQualified(selected)) throw new ArgumentException("Root must be absolute.");
        selected = Path.TrimEndingDirectorySeparator(Path.GetFullPath(selected));
        if (!selected.Equals(tempBase, StringComparison.OrdinalIgnoreCase)
            && !selected.Equals(guestBase, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Root must be the dedicated guest or user Temp calibration base.");
        string work = Path.Combine(selected, runId);
        for (DirectoryInfo? dir = new DirectoryInfo(work); dir is not null; dir = dir.Parent)
            if (dir.Exists && dir.Attributes.HasFlag(FileAttributes.ReparsePoint))
                throw new InvalidOperationException("Reparse point in calibration path: " + dir.FullName);
        return work;
    }

    private static void Log(List<object> events, string action, string target) =>
        events.Add(new { utc = DateTimeOffset.UtcNow, action, target });

    private static byte[] MakeDecoy(int i)
    {
        byte[] bytes = new byte[BytesEach];
        Encoding.UTF8.GetBytes($"KSword synthetic decoy {i:000}; no user data\n").CopyTo(bytes, 0);
        for (int j = 128; j < bytes.Length; j++) bytes[j] = (byte)((i + j) & 0xff);
        return bytes;
    }

    private static async Task<int> Main(string[] args)
    {
        if (args.Length == 1 && args[0] is "--help" or "-h")
        {
            Console.WriteLine("Usage: sample.exe [--root <approved calibration base>]");
            return 0;
        }
        if (args.Length == 1 && args[0] == "--noop") return 0;
        if (!InApprovedGuest())
        {
            Console.Error.WriteLine("Refused: run only from the VMware guest incoming directory.");
            return 2;
        }
        string runId = Guid.NewGuid().ToString("N")[..12];
        string root;
        try { root = WorkDirectory(args, runId); }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            Console.Error.WriteLine(ex.Message);
            return 2;
        }
        var events = new List<object>();
        string runName = "KSwordCalibration-" + runId;
        string? startupFile = null;
        string? error = null;
        int result = 0;
        try
        {
            Directory.CreateDirectory(root);
            string decoys = Path.Combine(root, "decoys");
            string replicas = Path.Combine(root, "replica");
            Directory.CreateDirectory(decoys);
            Directory.CreateDirectory(replicas);
            Log(events, "run-start", root);
            for (int i = 0; i < Count; i++)
            {
                string path = Path.Combine(decoys, $"document-{i:000}.txt");
                await File.WriteAllBytesAsync(path, MakeDecoy(i));
                Log(events, "file-created", path);
            }
            await Task.Delay(500);
            for (int i = 0; i < Count; i++)
            {
                string path = Path.Combine(decoys, $"document-{i:000}.txt");
                byte[] data = await File.ReadAllBytesAsync(path);
                for (int j = 0; j < data.Length; j++) data[j] ^= 0x5a;
                await File.WriteAllBytesAsync(path, data);
                Log(events, "file-rewritten", path);
                string renamed = Path.ChangeExtension(path, ".locked");
                File.Move(path, renamed);
                Log(events, "file-renamed", renamed);
                if (i < 6) { File.Delete(renamed); Log(events, "file-deleted", renamed); }
            }
            await Task.Delay(500);
            string sourceExe = Path.GetFullPath(Environment.ProcessPath!);
            if (new FileInfo(sourceExe).Length > MaxCopyBytes)
                throw new InvalidOperationException("Self-copy exceeds 128 MiB limit.");
            string replica = Path.Combine(replicas, "calibration-replica.exe");
            File.Copy(sourceExe, replica, overwrite: false);
            Log(events, "self-copy-created-not-executed", replica);
            // This exact staged sample path lets the guest's post-run startup
            // snapshot correlate the harmless Run entry to the submitted EXE.
            using (RegistryKey key = Registry.CurrentUser.CreateSubKey(RunKey, writable: true)
                ?? throw new InvalidOperationException("Could not open HKCU Run key"))
                key.SetValue(runName, $"\"{sourceExe}\" --noop", RegistryValueKind.String);
            Log(events, "hkcu-run-value-created-pending-vm-rollback", $@"HKCU\{RunKey}\{runName}");

            string startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
            if (string.IsNullOrWhiteSpace(startup) || !Directory.Exists(startup))
            {
                Log(events, "startup-skipped", "Current-user Startup directory unavailable");
            }
            else
            {
                startupFile = Path.Combine(startup, runName + ".cmd");
                await using (var stream = new FileStream(startupFile, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                await using (var writer = new StreamWriter(stream, new UTF8Encoding(false)))
                    await writer.WriteLineAsync("@exit /b 0");
                Log(events, "inert-startup-cmd-created-not-executed-pending-vm-rollback", startupFile);
            }

            // This string is an intent annotation only; no process/API executes it.
            Log(events, "shadow-delete-intent-only-never-executed", "vssadmin delete shadows /all /quiet");
            await Task.Delay(1500);
        }
        catch (Exception ex) { error = ex.GetType().Name + ": " + ex.Message; result = 1; }
        finally
        {
            try
            {
                Directory.CreateDirectory(root);
                var manifest = new
                {
                    schema = "ksword-behavior-calibration-v1",
                    runId,
                    workRoot = root,
                    utcCompleted = DateTimeOffset.UtcNow,
                    bounds = new { decoyCount = Count, decoyBytesEach = BytesEach, maxSelfCopyBytes = MaxCopyBytes },
                    cleanup = new
                    {
                        runValue = "pending VM snapshot rollback; target --noop is inert",
                        startupCmd = startupFile is null ? "not-created" : "pending VM snapshot rollback; content is @exit /b 0",
                        decoyFiles = "pending VM snapshot rollback"
                    },
                    shadowCopyDeletion = "intent-logged-only; command-never-executed",
                    operations = events,
                    error
                };
                string manifestPath = Path.Combine(root, "behavior-manifest.json");
                await File.WriteAllTextAsync(manifestPath, JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true }), Encoding.UTF8);
                Console.WriteLine("Calibration manifest: " + manifestPath);
            }
            catch (Exception ex) { Console.Error.WriteLine("Manifest write failed: " + ex.Message); result = 1; }
        }
        if (error is not null) Console.Error.WriteLine(error);
        return result;
    }
}
