## @hoajs/csrf

CSRF middleware for Hoa.

## Installation

```bash
$ npm i @hoajs/csrf --save
```

## Quick Start

```js
import { Hoa } from 'hoa'
import { csrf } from '@hoajs/csrf'

const app = new Hoa()
app.use(csrf())

app.use(async (ctx) => {
  ctx.res.body = `Hello, Hoa!`
})

export default app
```

## Documentation

The documentation is available on [hoa-js.com](https://hoa-js.com/middleware/csrf.html)

## Test (100% coverage)

```sh
$ npm test
```

## License

MIT
