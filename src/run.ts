import assert from 'assert'
import * as core from '@actions/core'
import * as ecr from '@aws-sdk/client-ecr'

type Inputs = {
  registryId: string | undefined
  repositoryName: string
  repositoryNotFoundErrorMessage: string
}

type Outputs = {
  repositoryURI: string
}

export const run = async (inputs: Inputs): Promise<Outputs> => {
  const client = new ecr.ECRClient({})
  core.info(`Describing the repository: ${inputs.repositoryName}`)
  let describe
  try {
    describe = await client.send(
      new ecr.DescribeRepositoriesCommand({
        registryId: inputs.registryId,
        repositoryNames: [inputs.repositoryName],
      }),
    )
  } catch (error) {
    if (ecr.RepositoryNotFoundException.isInstance(error)) {
      core.info(`Repository not found: ${error.message}`)
      const message = inputs.repositoryNotFoundErrorMessage.replace('{{repository-name}}', inputs.repositoryName)
      throw new Error(message)
    }
    throw error
  }
  assert(describe.repositories !== undefined, `describe.repositories must not be undefined`)
  assert.strictEqual(describe.repositories.length, 1)
  const repository = describe.repositories[0]
  assert(repository.repositoryUri !== undefined, `repository.repositoryUri must not be undefined`)
  core.info(`Repository found: ${JSON.stringify(repository, null, 2)}`)
  return {
    repositoryURI: repository.repositoryUri,
  }
}
