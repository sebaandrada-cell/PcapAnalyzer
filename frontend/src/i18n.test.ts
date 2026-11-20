import { test } from 'node:test'
import assert from 'node:assert/strict'
import { pickInitialLang, translate } from './i18n.ts'

test('a stored choice wins over the browser language', () => {
  assert.equal(pickInitialLang('es', ['en-US']), 'es')
  assert.equal(pickInitialLang('en', ['es-ES']), 'en')
})

test('without a stored choice the browser language decides', () => {
  assert.equal(pickInitialLang(null, ['es-AR', 'en']), 'es')
  assert.equal(pickInitialLang(null, ['en-GB']), 'en')
  assert.equal(pickInitialLang(null, ['de-DE', 'fr']), 'en')
  assert.equal(pickInitialLang(null, []), 'en')
})

test('API fallback messages exist in both languages', () => {
  for (const key of ['api.analysisFailed', 'api.analysisTimeout', 'api.reportFailed',
    'api.sessionDeleteFailed', 'api.emptyResponse', 'api.httpError']) {
    const es = translate('es', key, { status: 500 })
    const en = translate('en', key, { status: 500 })
    assert.notEqual(es, key, `es ${key}`)
    assert.notEqual(en, key, `en ${key}`)
    assert.notEqual(es, en, key)
  }
})
