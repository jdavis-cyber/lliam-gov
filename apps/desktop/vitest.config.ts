import { defineConfig, mergeConfig } from 'vitest/config'

import rendererConfig from './vite.config'

export default mergeConfig(
  rendererConfig,
  defineConfig({
    test: {
      setupFiles: ['./test/setup.ts']
    }
  })
)
