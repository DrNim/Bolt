﻿using System;

namespace Bolt
{

    public sealed class ExceptionThrownEventArgs : EventArgs
    {
        #region " Properties "

        public Exception Error
        {
            get { return _error; }
        }

        #endregion

        #region " Members "

        private Exception _error;

        #endregion

        #region " Constructor "

        public ExceptionThrownEventArgs(Exception error)
        {
            _error = error;
        }

        #endregion

    }

}