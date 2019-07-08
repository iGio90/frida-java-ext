# frida-java-ext

Some 'one-line' frida api to avoid code recycling here and there.


## install

```$xslt
git clone https://github.com/iGio90/frida-java-ext.git
npm install
npm link
```

### try it out
```$xslt
cd example
npm link frida-java-ext
npm install
npm run watch

# make your edits to index.ts
# inject the agent (quick att.py)
```

### api
- attachAllMethods
- attachConstructor
- attachMethod
- backtrace
- enumerateMethods

### example code
```typescript
import { JavaExt } from 'frida-java-ext';

/*
 * the args object in callback is an array of crafted objects holding argument data type and value/handle
 */

JavaExt.attachAllMethods('android.app.Activity', (args: any[], method: string, className: string) => {
    console.log(className, method, JSON.stringify(args));
});

JavaExt.attachConstructor('android.app.Activity', (args: any[]) => {
    console.log(JSON.stringify(args));
});

JavaExt.attachMethod('android.app.Activity', 'onCreate', (args: any[]) => {
    console.log(JSON.stringify(args));
});
```

### output
```
android.app.Activity attach [{"className":"android.content.Context","value":{"$handle":"0x3582","$weakRef":287}},{"className":"android.app.ActivityThread","value":{"$handle":"0x3562","$weakRef":290}},{"className":"android.app.Instrumentation","value":{"$handle":"0x3542","$weakRef":293}},{"className":"android.os.IBinder","value":{"$handle":"0x3522","$weakRef":296}},{"className":"int","value":120358391},{"className":"android.app.Application","value":{"$handle":"0x3502","$weakRef":299}},{"className":"android.content.Intent","value":{"$handle":"0x34e2","$weakRef":302}},{"className":"android.content.pm.ActivityInfo","value":{"$handle":"0x34c2","$weakRef":305}},{"className":"java.lang.CharSequence","value":{"$handle":"0x34a2","$weakRef":308}},{"className":"android.app.Activity","value":null},{"className":"java.lang.String","value":null},{"className":"android.app.Activity$NonConfigurationInstances","value":null},{"className":"android.content.res.Configuration","value":{"$handle":"0x3482","$weakRef":311}},{"className":"java.lang.String","value":"android"},{"className":"com.android.internal.app.IVoiceInteractor","value":null},{"className":"android.view.Window","value":null},{"className":"android.view.ViewRootImpl$ActivityConfigCallback","value":{"$handle":"0x3462","$weakRef":314}}]
android.app.Activity attachBaseContext [{"className":"android.content.Context","value":{"$handle":"0x343a","$weakRef":316}}]
android.app.Activity getSystemService [{"className":"java.lang.String","value":"layout_inflater"}]
android.app.Activity onWindowAttributesChanged [{"className":"android.view.WindowManager$LayoutParams","value":{"$handle":"0x33da","$weakRef":322}}]
android.app.Activity setTheme [{"className":"int","value":2131492890}]
android.app.Activity onApplyThemeResource [{"className":"android.content.res.Resources$Theme","value":{"$handle":"0x3526","$weakRef":327}},{"className":"int","value":2131492890},{"className":"boolean","value":true}]
android.app.Activity setTaskDescription [{"className":"android.app.ActivityManager$TaskDescription","value":{"$handle":"0x34a6","$weakRef":331}}]
android.app.Activity performCreate [{"className":"android.os.Bundle","value":null},{"className":"android.os.PersistableBundle","value":null}]
[{"className":"android.os.Bundle","value":null}]
```

```
Copyright (c) 2019 Giovanni (iGio90) Rocca

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
