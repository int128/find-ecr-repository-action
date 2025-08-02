import * as core from '@actions/core'
import { run } from './run.js'

try {
  const outputs = await run({
    registryId: core.getInput('registry-id') || undefined,
    repositoryName: core.getInput('repository-name', { required: true }),
    repositoryNotFoundErrorMessage: core.getInput('repository-not-found-error-message', { required: true }),
  })
  core.setOutput('repository-uri', outputs.repositoryURI)
} catch (e) {
  core.setFailed(e instanceof Error ? e : String(e))
  console.error(e)
}
