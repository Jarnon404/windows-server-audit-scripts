BeforeDiscovery {
    $DiscoveryRepositoryRoot = Split-Path -Parent $PSScriptRoot

    $DiscoveryScripts = Get-ChildItem `
        -Path (Join-Path $DiscoveryRepositoryRoot 'scripts') `
        -Filter '*.ps1' `
        -Recurse `
        -File
}

Describe 'Repository structure' {
    BeforeAll {
        $RepositoryRoot = Split-Path -Parent $PSScriptRoot
    }

    It 'Has a README' {
        Test-Path (Join-Path $RepositoryRoot 'README.md') | Should -BeTrue
    }

    It 'Has a LICENSE file' {
        Test-Path (Join-Path $RepositoryRoot 'LICENSE') | Should -BeTrue
    }

    It 'Has documentation folder' {
        Test-Path (Join-Path $RepositoryRoot 'docs') | Should -BeTrue
    }

    It 'Has script folder' {
        Test-Path (Join-Path $RepositoryRoot 'scripts') | Should -BeTrue
    }
}

Describe 'PowerShell scripts' {
    BeforeAll {
        $RepositoryRoot = Split-Path -Parent $PSScriptRoot
        $RuntimeScripts = Get-ChildItem `
            -Path (Join-Path $RepositoryRoot 'scripts') `
            -Filter '*.ps1' `
            -Recurse `
            -File
    }

    It 'Contains PowerShell scripts' {
        $RuntimeScripts.Count | Should -BeGreaterThan 0
    }

    It 'PowerShell script <Name> parses successfully' -ForEach $DiscoveryScripts {
        $Tokens = $null
        $ParseErrors = $null

        [System.Management.Automation.Language.Parser]::ParseFile(
            $_.FullName,
            [ref]$Tokens,
            [ref]$ParseErrors
        ) | Out-Null

        $ParseErrors.Count | Should -Be 0
    }

    It 'PowerShell script <Name> has comments' -ForEach $DiscoveryScripts {
        $Content = Get-Content -Path $_.FullName -Raw
        $Content | Should -Match '#'
    }
}

Describe 'Repository hygiene' {
    BeforeAll {
        $RepositoryRoot = Split-Path -Parent $PSScriptRoot
    }

    It 'Does not contain generated report files in tracked project areas' {
        $GeneratedExtensions = @(
            '.csv',
            '.xlsx',
            '.html',
            '.json',
            '.log',
            '.zip',
            '.7z',
            '.bak',
            '.tmp'
        )

        $ExcludedDirs = @(
            '.git',
            '.github',
            'tests',
            'docs',
            'examples'
        )

        $Files = Get-ChildItem -Path $RepositoryRoot -Recurse -File | Where-Object {
            $FullName = $_.FullName
            -not ($ExcludedDirs | Where-Object {
                $FullName -match "[\\/]$($_)([\\/]|$)"
            })
        }

        $Generated = $Files | Where-Object {
            $GeneratedExtensions -contains $_.Extension.ToLowerInvariant()
        }

        $Generated.Count | Should -Be 0
    }
}
