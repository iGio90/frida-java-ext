export module JavaExt {

    /**
     * attach to all methods of the provided java class
     *
     * @param className
     * @param callback
     */
    export function attachAllMethods(className: string, callback: Function) {
        Java.performNow(function () {
            const methods = enumerateMethods(className);
            methods.forEach(method => {
                hookInJvm(className, method, callback);
            })
        });
    }

    /**
     * attach to to the provided java class constructor (all overloads)
     *
     * @param className
     * @param callback
     */
    export function attachConstructor(className: string, callback: Function) {
        Java.performNow(function () {
            hookInJvm(className, '$init', callback);
        });
    }

    /**
     * attach to to the provided java class method (all overloads)
     *
     * @param className
     * @param method
     * @param callback
     */
    export function attachMethod(className: string, method: string, callback: Function) {
        Java.performNow(function () {
            hookInJvm(className, method, callback);
        });
    }

    /**
     * get the backtrace on the current context
     */
    export function backtrace() {
        return Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Exception").$new());
    }

    /**
     * enumerate all the methods for the provided java class
     * 0xdea code -> https://github.com/0xdea/frida-scripts/blob/master/raptor_frida_android_trace.js
     *
     * @param className
     */
    export function enumerateMethods(className: string): string[] {
        const clazz = Java.use(className);
        const methods: string[] = clazz.class.getDeclaredMethods();
        clazz.$dispose();

        const parsedMethods: string[] = [];
        methods.forEach(function (method) {
            const m = method.toString().replace(className + ".",
                "TOKEN").match(/\sTOKEN(.*)\(/);
            if (m && m.length > 0) {
                parsedMethods.push(m[1]);
            }
        });
        return uniqueBy(parsedMethods);
    }

    function hookInJvm(className: string, method: string, callback: Function) {
        const handler = Java.use(className);

        const overloadCount = handler[method].overloads.length;

        if (overloadCount > 0) {
            for (let i = 0; i < overloadCount; i++) {
                const overload = handler[method].overloads[i];
                overload.implementation = function () {
                    const argsType: object[] = overload.argumentTypes;
                    const args = [];

                    for (let i=0;i<argsType.length;i++) {
                        const arg = argsType[i];
                        args.push({
                            'className': arg['className'],
                            'value': arguments[i]
                        });
                    }

                    const ret = callback.call(this, args, method, className);
                    if (typeof ret !== 'undefined') {
                        return ret;
                    }
                    return overload.apply(this, arguments);
                }
            }
        }
    }

    function uniqueBy(array: any[]): any[] {
        const seen: {[key: string]: any} = {};
        return array.filter(function (item) {
            const k = JSON.stringify(item);
            return seen.hasOwnProperty(k) ? false : (seen[k] = true);
        });
    }
}