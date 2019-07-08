import {JavaContext, JavaExt} from 'frida-java-ext';

function simpleCallback(context: JavaContext) {
    // print call arguments
    console.log(context.className, context.method, JSON.stringify(context.arguments));

    // print call arguments with types and details
    console.log(context.className, context.method, JSON.stringify(context.formattedArguments));

    // detach the hook
    context.detach();
}

Java.performNow(() => {
    JavaExt.attachAllMethods('android.app.Activity', simpleCallback);

    JavaExt.attachConstructor('android.app.Activity', function (context: JavaContext) {
        console.log(context.method, 'hit!')
    });

    JavaExt.attachMethod('java.lang.Object', 'toString', {
        onEnter(context: JavaContext): void {
            console.log(context.className, context.method);
        },
        onLeave(retval: object): any {
            console.log(JSON.stringify(retval));
            return '';
        }
    });
});
