import { transform } from 'lightningcss';
import { join } from 'node:path';

let { code } = transform({
  filename: 'style.dev.css',
  code: Buffer.from(await Bun.file(join(import.meta.dir, '../style.dev.css')).text()),
  minify: true
});

await Bun.write(join(import.meta.dir, '../style.prod.css'), code);