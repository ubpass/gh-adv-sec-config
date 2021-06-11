/**
 * @name Unsafe deserialisation using jackson-databind polymorphic types
 * @description Using unsafe configuration for jackson-databind JsonTypeInfo, which can allow an attacker to
 * deserialise arbitrary java objects and execute code on the victim's host
 * @kind problem
 * @id java/jackson-databind-deserialisation
 * @tags security
 *       custom/CWE-502
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.Statement

class UnsafeJsonTypeAnnotation extends Annotation {
    UnsafeJsonTypeAnnotation() {
        this.getType().hasQualifiedName("com.fasterxml.jackson.annotation", "JsonTypeInfo") and
        exists (EnumConstant ec |
            ec.getDeclaringType().getEnclosingType() = this.getType() and
            ec.getType().hasName("Id") and
            ec.getName() = "CLASS"
        )
    }
}

class SpringPostMappingMethod extends SpringControllerMethod {
    SpringPostMappingMethod() {
        this.getAnAnnotation().getType().hasName("PostMapping")
    }

    Parameter getRequestBodyParam() {
        this.getAParameter().getAnAnnotation().getType().hasName("RequestBody") and
        result = this.getAParameter()
    }
}

from UnsafeJsonTypeAnnotation ua, SpringPostMappingMethod sm
where
    sm.getRequestBodyParam().getType().(Class).getAField().getAnAnnotation() = ua and
    sm.getRequestBodyParam().getType().(Class).getAField().getType().(Class).getPackage().toString() = "java.lang"
select sm.getRequestBodyParam(), "Unsafe polymorphic deserialisation from arbitrary user input in attribute $@.", ua, ua.getAnnotatedElement().toString()
