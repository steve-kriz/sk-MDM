/**
 * Test for .gitignore containing the dist-lambda output.
 */

import test from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';

const gitignorePath = path.resolve('./.gitignore');

test('Gitignore - backend/dist-lambda/ is in .gitignore', (t) => {
  const content = fs.readFileSync(gitignorePath, 'utf-8');
  const lines = content.split('\n');
  
  const hasDistLambda = lines.some(line => {
    // Trim and skip empty lines and comments
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) return false;
    
    // Check for backend/dist-lambda/ line
    return trimmed === 'backend/dist-lambda/';
  });
  
  assert.ok(hasDistLambda, '.gitignore should contain "backend/dist-lambda/"');
});
