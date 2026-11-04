import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';

const temporaryBase=path.resolve(tmpdir());
export const testOutput=mkdtempSync(path.join(temporaryBase,'aegis-test-'));
process.once('exit',()=>{
 const resolved=path.resolve(testOutput);
 if(path.dirname(resolved)!==temporaryBase||!path.basename(resolved).startsWith('aegis-test-'))return;
 rmSync(resolved,{recursive:true,force:true,maxRetries:3,retryDelay:100});
});
