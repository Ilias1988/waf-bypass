import { cpSync, existsSync, mkdtempSync, writeFileSync, rmSync } from 'fs'
import { tmpdir } from 'os'
import { join, resolve, dirname } from 'path'
import { spawnSync } from 'child_process'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const root = resolve(__dirname, '..')
const distDir = resolve(root, 'dist')
const remote = 'https://github.com/Ilias1988/waf-bypass.git'
const branch = 'gh-pages'

if (!process.argv.includes('--confirm-deploy')) {
  throw new Error('Deployment not confirmed. Run: npm run deploy -- --confirm-deploy')
}

if (!existsSync(distDir)) {
  throw new Error('dist/ is missing. Run npm run build before deployment.')
}

const stagingDir = mkdtempSync(join(tmpdir(), 'waf-bypass-ghpages-'))

function runGit(args) {
  const result = spawnSync('git', args, {
    cwd: stagingDir,
    stdio: 'inherit',
    shell: false,
  })

  if (result.error) throw result.error
  if (result.status !== 0) {
    throw new Error(`git ${args[0]} failed with exit code ${result.status}`)
  }
}

try {
  cpSync(distDir, stagingDir, { recursive: true })
  writeFileSync(resolve(stagingDir, 'CNAME'), 'waf-bypass.dev\n')
  writeFileSync(resolve(stagingDir, '.nojekyll'), '')

  runGit(['init'])
  runGit(['checkout', '-b', branch])
  runGit(['add', '-A'])
  runGit(['commit', '-m', 'deploy: GitHub Pages'])
  runGit(['remote', 'add', 'origin', remote])
  runGit(['fetch', 'origin', branch])
  runGit(['push', 'origin', branch, '--force-with-lease'])

  console.log('Deployment completed and the gh-pages branch was updated.')
} finally {
  rmSync(stagingDir, { recursive: true, force: true })
}
