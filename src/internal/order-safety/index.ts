export type RunFunction<T> = () => PromiseLike<T> | T;

interface IWorkQueueItem<T> {
  fn: RunFunction<T>;
  resolve: () => T;
  reject: (err: any) => void;
}

function removeReduce<T>(arr: T[], reducer: (chain: T, item: T) => T, initial: T): T {
  let prev = initial;
  arr.forEach((item: T, index: number, object: T[]) => {
    prev = reducer(prev, item);
    object.splice(index, 1);
  });
  return prev;
}

export default class OrderSafety {
  private _lock: number = 0;
  private _workQueue: IWorkQueueItem<any>[] = [];

  private _runQueue(): Promise<void> {
    return removeReduce<any>(this._workQueue,
      (chain, item) => chain.finally(() => new Promise((resolve) => {
        Promise.resolve(item.fn())
          .then(() => {
            item.resolve();
          })
          .catch((e) => {
            item.reject(e);
          })
          .finally(resolve);
      })),
      Promise.resolve()).then(() => {
      if (this._workQueue.length > 0) {
        this._runQueue();
      }
    });
  }

  run<T>(fn: RunFunction<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      if (this._lock) {
        this._workQueue.push({
          fn,
          resolve,
          reject
        });
        return;
      }

      this._lock = 1;
      Promise.resolve(fn())
        .then(resolve)
        .catch(reject)
        .finally(() => this._runQueue()
          .finally(() => {
            this._lock = 0;
          }));
    });
  }
}
