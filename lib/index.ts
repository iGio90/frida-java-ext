export module JavaExt {

    export function attachConstructor(className: string, callback: Function) {
        Java.performNow(function () {
            hookInJvm(className, '$init', callback);
        });
    }

    export function attachMethod(className: string, method: string, callback: Function) {
        Java.performNow(function () {
            hookInJvm(className, method, callback);
        });
    }

    export function attachAllMethods(className: string, callback: Function) {
        Java.performNow(function () {
            const methods = enumerateJavaMethods(className);
            methods.forEach(method => {
                hookInJvm(className, method, callback);
            })
        });
    }
    
    export function enumerateJavaMethods(className: string): string[] {
        // 0xdea code -> https://github.com/0xdea/frida-scripts/blob/master/raptor_frida_android_trace.js
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
                    this.detach = function () {
                        overload.implementation = function () {
                            return overload.apply(this, arguments);
                        };
                    };
                    const ret = callback.call(this, arguments, method, className);
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