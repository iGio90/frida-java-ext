import { JavaExt } from 'frida-java-ext';

/*
 * the args object in callback is an array of crafted objects holding argument data type and value/handle
 */

Java.performNow(() => {
    JavaExt.attachAllMethods('android.app.Activity', (args: any[], method: string, className: string) => {
        console.log(className, method, JSON.stringify(args));
    });

    JavaExt.attachConstructor('android.app.Activity', (args: any[]) => {
        console.log(JSON.stringify(args));
    });

    JavaExt.attachMethod('android.app.Activity', 'onCreate', (args: any[]) => {
        console.log(JSON.stringify(args));
    });
});
