%Module(name=keystore,
        version=0,
        keyword_arguments="Optional")

%Include keystore/qgskeystoreutils.sip




// QPair<TYPE, TYPE> is implemented as a Python 2-element tuple.
template<TYPE1, TYPE2>
%MappedType QPair<TYPE1, TYPE2> /DocType="tuple-of-TYPE1-TYPE2"/
{
%TypeHeaderCode
#include <qpair.h>
%End

%ConvertFromTypeCode
    // Create the tuple.
    PyObject *tup = PyTuple_New(2);

    if (!tup)
        return 0;

    PyObject *obj;

    // Convert the first part.
    TYPE1 *t = new TYPE1(sipCpp->first);

    obj = sipConvertFromNewType(t, sipType_TYPE1, sipTransferObj);

    if (!obj)
    {
        delete t;

        Py_DECREF(tup);
        return 0;
    }

    PyTuple_SET_ITEM(tup, 0, obj);

    // Convert the second part.
    TYPE2 *tt = new TYPE2(sipCpp->second);

    obj = sipConvertFromNewType(tt, sipType_TYPE2, sipTransferObj);

    if (!obj)
    {
        delete tt;

        Py_DECREF(tup);
        return 0;
    }

    PyTuple_SET_ITEM(tup, 1, obj);

    return tup;
%End

%ConvertToTypeCode
	// Check the type if that is all that is required.
    if (sipIsErr == NULL)
        return (PyTuple_Size(sipPy) == 2 && 
		sipCanConvertToType(PyTuple_GET_ITEM(sipPy, 0), sipType_TYPE1, SIP_NOT_NONE) &&
		sipCanConvertToType(PyTuple_GET_ITEM(sipPy, 1), sipType_TYPE2, SIP_NOT_NONE));

    QPair<TYPE1, TYPE2> *qp = new QPair<TYPE1, TYPE2>;

	// fist element conversion
    int state;
    TYPE1 *t = reinterpret_cast<TYPE1 *>(sipConvertToType(PyTuple_GET_ITEM(sipPy, 0), sipType_TYPE1, sipTransferObj, SIP_NOT_NONE, &state, sipIsErr));

    if (*sipIsErr)
    {
        sipReleaseType(t, sipType_TYPE1, state);

        delete qp;
        return 0;
    }

    qp->first = *t;
    sipReleaseType(t, sipType_TYPE1, state);

	// second element conversion
    TYPE2 *tt = reinterpret_cast<TYPE2 *>(sipConvertToType(PyTuple_GET_ITEM(sipPy, 1), sipType_TYPE2, sipTransferObj, SIP_NOT_NONE, &state, sipIsErr));

    if (*sipIsErr)
    {
        sipReleaseType(t, sipType_TYPE1, state);
        sipReleaseType(tt, sipType_TYPE2, state);

        delete qp;
        return 0;
    }

    qp->second = *tt;
    sipReleaseType(tt, sipType_TYPE2, state);

    *sipCppPtr = qp;

    return sipGetState(sipTransferObj);
%End
};
	